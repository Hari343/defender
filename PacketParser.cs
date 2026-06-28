using WpfApp2;
using System;
using System.Globalization;

internal class PacketParser
{
    public static Packet? ParsePacket(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        var fields = line.Split('\t');

        if (fields.Length < 13)
            return null;

        var packet = new Packet();

        packet.PacketNumber = ParseInt(fields[0]);
        packet.Timestamp = ParseDouble(fields[1]);

        packet.SourceAddress = fields[2];
        packet.DestinationAddress = fields[3];

        packet.Protocol = fields[4];
        packet.PacketSize = ParseInt(fields[5]);

        packet.SourcePort = ParseNullableInt(fields[6]);
        packet.DestinationPort = ParseNullableInt(fields[7]);

        packet.SequenceNumber = ParseNullableInt(fields[9]);
        packet.AcknowledgmentNumber = ParseNullableInt(fields[10]);
        packet.WindowSize = ParseNullableInt(fields[11]);
        packet.PayloadLength = ParseNullableInt(fields[12]);

        packet.IsTcp = packet.Protocol == "TCP";

        ParseTcpFlags(packet, fields[8]);

        return packet;
    }

    private static void ParseTcpFlags(Packet packet, string flags)
    {
        if (string.IsNullOrWhiteSpace(flags))
            return;

        var value = Convert.ToUInt32(flags, 16);

        packet.Flags = flags;

        packet.IsFin = (value & 0x01) != 0;
        packet.IsSyn = (value & 0x02) != 0;
        packet.IsReset = (value & 0x04) != 0;
        packet.IsAcknowledgment = (value & 0x10) != 0;
        packet.IsSynAck = packet.IsSyn && packet.IsAcknowledgment;
    }

    private static int ParseInt(string value)
    {
        int.TryParse(value, out int result);
        return result;
    }

    private static int? ParseNullableInt(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (int.TryParse(value, out int result))
        {
            return result;
        }

        return null;
    }

    private static double ParseDouble(string value)
    {
        double.TryParse(
            value,
            NumberStyles.Any,
            CultureInfo.InvariantCulture,
            out double result);

        return result;
    }
}

public class Packet
{

    // Packet number in the capture sequence
    public int PacketNumber { get; set; }


    // Timestamp of the packet (seconds since capture start)
    public double Timestamp { get; set; }


    // Source IP address
    public string SourceAddress { get; set; }


    // Destination IP address
    public string DestinationAddress { get; set; }


    // Protocol type (TCP, TLS)
    public string Protocol { get; set; }


    // Packet size
    public int PacketSize { get; set; }


    // Source port
    public int? SourcePort { get; set; }


    // Destination port
    public int? DestinationPort { get; set; }


    // TCP flags
    public string Flags { get; set; }


    // TCP sequence number
    public int? SequenceNumber { get; set; }


    // TCP acknowledgment number
    public int? AcknowledgmentNumber { get; set; }


    // TCP window size
    public int? WindowSize { get; set; }


    // Payload length
    public int? PayloadLength { get; set; }


    // Whether packet is a TCP packet
    public bool IsTcp { get; set; }


    // Whether packet is a TLS packet
    public bool IsTls { get; set; }


    // Whether packet has ACK flag set
    public bool IsAcknowledgment { get; set; }


    // Whether packet has SYN flag set
    public bool IsSyn { get; set; }


    // Whether packet has FIN flag set
    public bool IsFin { get; set; }


    // Whether packet has RST flag set
    public bool IsReset { get; set; }


    // Whether packet is a SYN-ACK 
    public bool IsSynAck { get; set; }


    // Additional TLS information
    public string TlsInfo { get; set; }


    // Returns a formatted string representation of the packet
    public override string ToString()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"[Packet {PacketNumber}] @ {Timestamp}s");
        sb.AppendLine($"  {SourceAddress}{(SourcePort.HasValue ? $":{SourcePort}" : "")} -> {DestinationAddress}{(DestinationPort.HasValue ? $":{DestinationPort}" : "")}");
        sb.AppendLine($"  Protocol: {Protocol} | Size: {PacketSize} bytes");

        if (IsTcp)
        {
            sb.AppendLine($"  TCP Flags: {Flags}");
            if (SequenceNumber.HasValue)
            {
                sb.AppendLine($"  Seq: {SequenceNumber}, Ack: {AcknowledgmentNumber}");
            }
        }
        else if (IsTls)
        {
            sb.AppendLine($"  TLS Info: {TlsInfo}");
        }

        return sb.ToString();
    }
}