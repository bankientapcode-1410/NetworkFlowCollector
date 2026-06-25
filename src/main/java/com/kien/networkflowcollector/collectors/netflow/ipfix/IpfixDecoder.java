package com.kien.networkflowcollector.collectors.netflow.ipfix;

import com.kien.networkflowcollector.collectors.netflow.NetFlowProtocolSupport;
import com.kien.networkflowcollector.collectors.netflow.template.TemplateCache;
import com.kien.networkflowcollector.collectors.netflow.template.TemplateField;
import com.kien.networkflowcollector.collectors.netflow.template.TemplateRecord;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class IpfixDecoder {

    private final TemplateCache templates = new TemplateCache();

    public List<RawFlowRecord> decode(ByteBuf packet, String exporterIp, Instant receivedAt) {
        return decode(packet, exporterIp, -1, receivedAt);
    }

    public List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt) {
        Objects.requireNonNull(packet, "packet");
        Objects.requireNonNull(exporterIp, "exporterIp");
        Objects.requireNonNull(receivedAt, "receivedAt");

        int base = packet.readerIndex();
        int readableLength = packet.readableBytes();
        if (readableLength < IpfixProtocol.HEADER_LENGTH) {
            throw new IpfixDecodeException("IPFIX message too short: " + readableLength + " bytes");
        }

        int version = packet.getUnsignedShort(base);
        if (version != IpfixProtocol.VERSION) {
            throw new IpfixDecodeException("Unsupported IPFIX version: " + version);
        }

        int messageLength = packet.getUnsignedShort(base + 2);
        if (messageLength < IpfixProtocol.HEADER_LENGTH) {
            throw new IpfixDecodeException("Invalid IPFIX message length: " + messageLength);
        }
        if (messageLength > readableLength) {
            throw new IpfixDecodeException(
                    "IPFIX message truncated: expected "
                            + messageLength
                            + " bytes but got "
                            + readableLength);
        }

        long exportSeconds = packet.getUnsignedInt(base + 4);
        long sequenceNumber = packet.getUnsignedInt(base + 8);
        long observationDomainId = packet.getUnsignedInt(base + 12);
        Instant exportTime = NetFlowProtocolSupport.exportTimeSeconds(exportSeconds);
        String exporterKey = IpfixProtocol.exporterKey(exporterIp, exporterPort);

        List<RawFlowRecord> out = new ArrayList<>();
        int offset = base + IpfixProtocol.HEADER_LENGTH;
        int end = base + messageLength;
        int recordIndex = 0;
        while (offset + 4 <= end) {
            int setId = packet.getUnsignedShort(offset);
            int setLength = packet.getUnsignedShort(offset + 2);
            if (setLength < 4) {
                throw new IpfixDecodeException("Invalid IPFIX Set length: " + setLength);
            }
            int setEnd = offset + setLength;
            if (setEnd > end) {
                throw new IpfixDecodeException(
                        "IPFIX Set truncated: expected end "
                                + setEnd
                                + " but message ends at "
                                + end);
            }

            int bodyOffset = offset + 4;
            if (setId == IpfixProtocol.TEMPLATE_SET_ID) {
                parseTemplateSet(packet, bodyOffset, setEnd, exporterKey, observationDomainId);
            } else if (setId == IpfixProtocol.OPTIONS_TEMPLATE_SET_ID) {
                parseOptionsTemplateSet(packet, bodyOffset, setEnd, exporterKey, observationDomainId);
            } else if (setId >= IpfixProtocol.MIN_DATA_SET_ID) {
                recordIndex =
                        parseDataSet(
                                packet,
                                bodyOffset,
                                setEnd,
                                setId,
                                exporterIp,
                                exporterKey,
                                receivedAt,
                                messageLength,
                                exportSeconds,
                                sequenceNumber,
                                observationDomainId,
                                exportTime,
                                recordIndex,
                                out);
            }

            offset = setEnd;
        }

        if (offset < end && !NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
            throw new IpfixDecodeException("IPFIX message has trailing partial Set header");
        }
        return out;
    }

    private void parseTemplateSet(ByteBuf packet, int offset, int end, String exporterKey, long observationDomainId) {
        while (offset < end) {
            if (end - offset < 4) {
                requirePadding(packet, offset, end, "IPFIX template padding");
                return;
            }
            if (NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
                return;
            }

            int templateId = packet.getUnsignedShort(offset);
            int fieldCount = packet.getUnsignedShort(offset + 2);
            offset += 4;
            if (templateId < IpfixProtocol.MIN_DATA_SET_ID) {
                throw new IpfixDecodeException("Invalid IPFIX template id: " + templateId);
            }
            if (fieldCount == 0) {
                templates.remove(IpfixProtocol.TEMPLATE_PROTOCOL, exporterKey, observationDomainId, templateId);
                continue;
            }

            List<TemplateField> fields = new ArrayList<>(fieldCount);
            for (int i = 0; i < fieldCount; i++) {
                ParsedField parsed = parseFieldSpecifier(packet, offset, end, false);
                fields.add(parsed.field());
                offset = parsed.nextOffset();
            }
            templates.put(
                    IpfixProtocol.TEMPLATE_PROTOCOL,
                    exporterKey,
                    observationDomainId,
                    new TemplateRecord(templateId, fields, false));
        }
    }

    private void parseOptionsTemplateSet(
            ByteBuf packet, int offset, int end, String exporterKey, long observationDomainId) {
        while (offset < end) {
            if (end - offset < 4) {
                requirePadding(packet, offset, end, "IPFIX options template padding");
                return;
            }
            if (NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
                return;
            }

            int templateId = packet.getUnsignedShort(offset);
            int fieldCount = packet.getUnsignedShort(offset + 2);
            offset += 4;
            if (templateId < IpfixProtocol.MIN_DATA_SET_ID) {
                throw new IpfixDecodeException("Invalid IPFIX options template id: " + templateId);
            }
            if (fieldCount == 0) {
                templates.remove(IpfixProtocol.TEMPLATE_PROTOCOL, exporterKey, observationDomainId, templateId);
                continue;
            }
            if (end - offset < 2) {
                throw new IpfixDecodeException("IPFIX options template missing scope field count");
            }
            int scopeFieldCount = packet.getUnsignedShort(offset);
            offset += 2;
            if (scopeFieldCount > fieldCount) {
                throw new IpfixDecodeException("IPFIX options scope field count exceeds field count");
            }

            List<TemplateField> fields = new ArrayList<>(fieldCount);
            for (int i = 0; i < fieldCount; i++) {
                ParsedField parsed = parseFieldSpecifier(packet, offset, end, i < scopeFieldCount);
                fields.add(parsed.field());
                offset = parsed.nextOffset();
            }
            templates.put(
                    IpfixProtocol.TEMPLATE_PROTOCOL,
                    exporterKey,
                    observationDomainId,
                    new TemplateRecord(templateId, fields, true));
        }
    }

    private ParsedField parseFieldSpecifier(ByteBuf packet, int offset, int end, boolean scope) {
        if (end - offset < 4) {
            throw new IpfixDecodeException("IPFIX field specifier truncated");
        }
        int rawType = packet.getUnsignedShort(offset);
        boolean enterpriseSpecific = (rawType & 0x8000) != 0;
        int type = rawType & 0x7fff;
        int length = packet.getUnsignedShort(offset + 2);
        offset += 4;
        long enterpriseNumber = 0;
        if (enterpriseSpecific) {
            if (end - offset < 4) {
                throw new IpfixDecodeException("IPFIX enterprise field specifier truncated");
            }
            enterpriseNumber = packet.getUnsignedInt(offset);
            offset += 4;
        }
        return new ParsedField(
                new TemplateField(type, length, enterpriseSpecific, enterpriseNumber, scope),
                offset);
    }

    private int parseDataSet(
            ByteBuf packet,
            int offset,
            int end,
            int templateId,
            String exporterIp,
            String exporterKey,
            Instant receivedAt,
            int messageLength,
            long exportSeconds,
            long sequenceNumber,
            long observationDomainId,
            Instant exportTime,
            int recordIndex,
            List<RawFlowRecord> out) {
        TemplateRecord template =
                templates.get(IpfixProtocol.TEMPLATE_PROTOCOL, exporterKey, observationDomainId, templateId);
        if (template == null) {
            throw new IpfixDecodeException(
                    "Missing IPFIX template "
                            + templateId
                            + " for exporter "
                            + exporterIp
                            + " observationDomainId "
                            + observationDomainId);
        }
        if (template.optionsTemplate()) {
            return recordIndex;
        }

        while (offset < end) {
            if (NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
                return recordIndex;
            }
            DecodedRecord decoded =
                    decodeRecord(
                            packet,
                            offset,
                            end,
                            template,
                            recordIndex,
                            messageLength,
                            exportSeconds,
                            sequenceNumber,
                            observationDomainId,
                            exportTime);
            if (decoded == null) {
                requirePadding(packet, offset, end, "IPFIX data Set padding");
                return recordIndex;
            }
            out.add(new RawFlowRecord(IpfixProtocol.SOURCE_TYPE, exporterIp, receivedAt, decoded.fields()));
            offset = decoded.nextOffset();
            recordIndex++;
        }
        return recordIndex;
    }

    private DecodedRecord decodeRecord(
            ByteBuf packet,
            int offset,
            int end,
            TemplateRecord template,
            int recordIndex,
            int messageLength,
            long exportSeconds,
            long sequenceNumber,
            long observationDomainId,
            Instant exportTime) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("version", IpfixProtocol.VERSION);
        fields.put("message_length", messageLength);
        fields.put("record_index", recordIndex);
        fields.put("export_time", exportTime);
        fields.put("export_time_seconds", exportSeconds);
        fields.put("sequence_number", sequenceNumber);
        fields.put("observation_domain_id", observationDomainId);
        fields.put("template_id", template.templateId());

        int fieldOffset = offset;
        for (TemplateField field : template.fields()) {
            int valueLength = field.length();
            if (field.variableLength()) {
                VariableLength variableLength = readVariableLength(packet, fieldOffset, end);
                if (variableLength == null) {
                    return null;
                }
                fieldOffset = variableLength.valueOffset();
                valueLength = variableLength.length();
            }
            if (fieldOffset + valueLength > end) {
                return null;
            }
            IpfixProtocol.putField(fields, field, packet, fieldOffset, valueLength, exportTime);
            fieldOffset += valueLength;
        }
        if (fieldOffset == offset) {
            throw new IpfixDecodeException("IPFIX template produced an empty data record");
        }
        IpfixProtocol.finishRecord(fields, exportTime);
        return new DecodedRecord(fields, fieldOffset);
    }

    private VariableLength readVariableLength(ByteBuf packet, int offset, int end) {
        if (offset >= end) {
            return null;
        }
        int firstLength = packet.getUnsignedByte(offset);
        if (firstLength < 255) {
            return new VariableLength(firstLength, offset + 1);
        }
        if (end - offset < 3) {
            return null;
        }
        return new VariableLength(packet.getUnsignedShort(offset + 1), offset + 3);
    }

    private static void requirePadding(ByteBuf packet, int offset, int end, String label) {
        if (!NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
            throw new IpfixDecodeException(label + " contains non-zero bytes");
        }
    }

    private record ParsedField(TemplateField field, int nextOffset) {}

    private record VariableLength(int length, int valueOffset) {}

    private record DecodedRecord(Map<String, Object> fields, int nextOffset) {}
}
