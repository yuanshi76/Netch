using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Netch.Services.Dns;

// The wire parser is shared by the listener, remote validation and offline regression tests.
public static class DnsWire
{
    public readonly record struct Question(string Name, ushort Type, ushort Class, int End);
    public static ushort U16(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
    public static uint U32(ReadOnlySpan<byte> data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4));
    public static void Put16(Span<byte> data, int offset, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(data.Slice(offset, 2), value);

    public static string ReadName(byte[] data, ref int offset)
    {
        var cursor = offset;
        var end = -1;
        var labels = new List<string>();
        var seen = new HashSet<int>();
        var total = 1;
        while (true)
        {
            if (cursor >= data.Length || !seen.Add(cursor)) throw new InvalidDataException("Invalid DNS name.");
            var length = data[cursor++];
            if (length == 0) { offset = end < 0 ? cursor : end; return string.Join('.', labels); }
            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= data.Length) throw new InvalidDataException("Truncated DNS pointer.");
                end = end < 0 ? cursor + 1 : end;
                cursor = ((length & 0x3f) << 8) | data[cursor];
                continue;
            }
            if (length > 63 || cursor + length > data.Length || (total += length + 1) > 255)
                throw new InvalidDataException("Invalid DNS label.");
            var label = data.AsSpan(cursor, length);
            if (label.IndexOfAnyInRange((byte)0, (byte)32) >= 0 || label.Contains((byte)'.') || label.IndexOfAnyInRange((byte)127, byte.MaxValue) >= 0)
                throw new InvalidDataException("Unsupported DNS label.");
            labels.Add(Encoding.ASCII.GetString(label));
            cursor += length;
        }
    }

    public static Question ParseQuestion(byte[] packet)
    {
        if (packet.Length < 12 || U16(packet, 4) != 1) throw new InvalidDataException("Exactly one DNS question is required.");
        var offset = 12;
        var name = ReadName(packet, ref offset);
        if (offset + 4 > packet.Length) throw new InvalidDataException("Truncated DNS question.");
        return new(name, U16(packet, offset), U16(packet, offset + 2), offset + 4);
    }

    public static byte[] Query(string name, ushort type, ushort id = 0)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[12]);
        var trimmed = name.TrimEnd('.');
        var asciiName = trimmed.Length == 0 ? "" : new System.Globalization.IdnMapping().GetAscii(trimmed);
        foreach (var label in asciiName.Length == 0 ? Array.Empty<string>() : asciiName.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new InvalidDataException("Invalid DNS name.");
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }
        stream.WriteByte(0);
        stream.Write([(byte)(type >> 8), (byte)type, 0, 1]);
        if (stream.Length > 271) throw new InvalidDataException("DNS name too long.");
        var result = stream.ToArray();
        Put16(result, 0, id);
        Put16(result, 2, 0x0100);
        Put16(result, 4, 1);
        return result;
    }

    // Rebuild EDNS without client subnet/cookies. Preserve only DNSSEC DO/CD semantics.
    public static byte[] NormalizeQuery(byte[] packet)
    {
        var q = ParseQuestion(packet);
        if ((U16(packet, 2) & 0xf800) != 0 || q.Class != 1 || U16(packet, 6) != 0 || U16(packet, 8) != 0)
            throw new InvalidDataException("Unsupported DNS query.");
        var query = Query(q.Name, q.Type, U16(packet, 0));
        Put16(query, 2, (ushort)(0x0100 | (U16(packet, 2) & 0x0010)));
        var offset = q.End;
        var dnssec = false;
        var extraCount = U16(packet, 10);
        if (extraCount > 1) throw new InvalidDataException("Unsupported DNS additional records.");
        for (var i = 0; i < extraCount; i++)
        {
            var owner = ReadName(packet, ref offset);
            if (offset + 10 > packet.Length || U16(packet, offset) != 41 || owner.Length != 0)
                throw new InvalidDataException("Invalid EDNS.");
            if ((U32(packet, offset + 4) & 0x00ff0000) != 0) throw new InvalidDataException("Unsupported EDNS version.");
            dnssec |= (U32(packet, offset + 4) & 0x8000) != 0;
            offset += 10 + U16(packet, offset + 8);
        }
        if (offset != packet.Length) throw new InvalidDataException("Invalid DNS message length.");
        if (extraCount == 0) return query;
        var withEdns = new byte[query.Length + 11];
        query.CopyTo(withEdns, 0);
        Put16(withEdns, 10, 1);
        var p = query.Length;
        Put16(withEdns, p + 1, 41);
        Put16(withEdns, p + 3, 1232);
        if (dnssec) withEdns[p + 7] = 0x80;
        return withEdns;
    }

    public static byte[] Error(byte[] query, ushort code)
    {
        byte[] result;
        try { var q = ParseQuestion(query); result = Query(q.Name, q.Type, U16(query, 0)); }
        catch (Exception e) when (e is InvalidDataException or ArgumentException) { result = new byte[12]; if (query.Length >= 2) query.AsSpan(0, 2).CopyTo(result); }
        var flags = query.Length >= 4 ? U16(query, 2) & 0x0110 : 0;
        Put16(result, 2, (ushort)(0x8080 | flags | code));
        return result;
    }

    public static void ValidateResponse(byte[] query, byte[] response)
    {
        if (response.Length < 12 || response.Length > 65535 || (U16(response, 2) & 0xfa00) != 0x8000 || U16(query, 0) != U16(response, 0))
            throw new InvalidDataException("Invalid/truncated remote DNS response.");
        var expected = ParseQuestion(query);
        var actual = ParseQuestion(response);
        if (!expected.Name.Equals(actual.Name, StringComparison.OrdinalIgnoreCase) || expected.Type != actual.Type || expected.Class != actual.Class)
            throw new InvalidDataException("Remote DNS question mismatch.");
        foreach (var record in Records(response))
        {
            if (record.Type == 41 && (record.Ttl >> 24) != 0)
                throw new InvalidDataException("Extended DNS failure response.");
            if ((record.Type == 1 && record.Length != 4) || (record.Type == 28 && record.Length != 16))
                throw new InvalidDataException("Invalid address record.");
        }
        _ = Addresses(response); // Validate CNAME compression before forwarding or caching.
    }

    public readonly record struct Record(string Name, ushort Type, ushort Class, uint Ttl, int TtlOffset, int DataOffset, int Length, bool IsAnswer);
    public static IEnumerable<Record> Records(byte[] response)
    {
        var offset = ParseQuestion(response).End;
        var answers = U16(response, 6);
        var count = answers + U16(response, 8) + U16(response, 10);
        if (count > 4096) throw new InvalidDataException("Too many DNS records.");
        for (var i = 0; i < count; i++)
        {
            var name = ReadName(response, ref offset);
            if (offset + 10 > response.Length) throw new InvalidDataException("Truncated DNS record.");
            var length = U16(response, offset + 8);
            if (offset + 10 + length > response.Length) throw new InvalidDataException("Truncated DNS data.");
            var record = new Record(name, U16(response, offset), U16(response, offset + 2), U32(response, offset + 4), offset + 4, offset + 10, length, i < answers);
            offset += 10 + length;
            yield return record;
        }
        if (offset != response.Length) throw new InvalidDataException("Trailing DNS data.");
    }

    public static IPAddress[] Addresses(byte[] response)
    {
        var question = ParseQuestion(response);
        var records = Records(response).Where(r => r.IsAnswer && r.Class == 1).ToArray();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { question.Name };
        for (var pass = 0; pass < 16; pass++)
        {
            var added = false;
            foreach (var record in records.Where(r => r.Type == 5 && names.Contains(r.Name)))
            {
                var offset = record.DataOffset;
                var target = ReadName(response, ref offset);
                if (offset != record.DataOffset + record.Length) throw new InvalidDataException("Invalid CNAME.");
                added |= names.Add(target);
            }
            if (!added) break;
        }
        return records.Where(r => names.Contains(r.Name) && (r.Type == 1 && r.Length == 4 || r.Type == 28 && r.Length == 16))
            .Select(r => new IPAddress(response.AsSpan(r.DataOffset, r.Length))).ToArray();
    }
}
