package com.kien.networkflowcollector.plugins.netflow.v9;

import com.kien.networkflowcollector.plugins.netflow.NetFlowProtocolSupport;
import com.kien.networkflowcollector.plugins.netflow.template.TemplateCache;
import com.kien.networkflowcollector.plugins.netflow.template.TemplateField;
import com.kien.networkflowcollector.plugins.netflow.template.TemplateRecord;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class NetFlowV9Decoder {

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
        int length = packet.readableBytes();
        if (length < NetFlowV9Protocol.HEADER_LENGTH) {
            throw new NetFlowV9DecodeException("NetFlow v9 packet too short: " + length + " bytes");
        }

        int version = packet.getUnsignedShort(base);
        if (version != NetFlowV9Protocol.VERSION) {
            throw new NetFlowV9DecodeException("Unsupported NetFlow version: " + version);
        }

        int headerRecordCount = packet.getUnsignedShort(base + 2);
        long sysUptimeMillis = packet.getUnsignedInt(base + 4);
        long unixSeconds = packet.getUnsignedInt(base + 8);
        long flowSequence = packet.getUnsignedInt(base + 12);
        long sourceId = packet.getUnsignedInt(base + 16);
        Instant exportTime = NetFlowProtocolSupport.exportTimeSeconds(unixSeconds);
        String exporterKey = NetFlowV9Protocol.exporterKey(exporterIp, exporterPort);

        List<RawFlowRecord> out = new ArrayList<>();
        int offset = base + NetFlowV9Protocol.HEADER_LENGTH;
        int end = base + length;
        int recordIndex = 0;
        while (offset + 4 <= end) {
            int flowSetId = packet.getUnsignedShort(offset);
            int flowSetLength = packet.getUnsignedShort(offset + 2);
            if (flowSetLength < 4) {
                throw new NetFlowV9DecodeException("Invalid NetFlow v9 FlowSet length: " + flowSetLength);
            }
            int flowSetEnd = offset + flowSetLength;
            if (flowSetEnd > end) {
                throw new NetFlowV9DecodeException(
                        "NetFlow v9 FlowSet truncated: expected end "
                                + flowSetEnd
                                + " but packet ends at "
                                + end);
            }

            int bodyOffset = offset + 4;
            if (flowSetId == NetFlowV9Protocol.TEMPLATE_FLOWSET_ID) {
                parseTemplateFlowSet(packet, bodyOffset, flowSetEnd, exporterKey, sourceId);
            } else if (flowSetId == NetFlowV9Protocol.OPTIONS_TEMPLATE_FLOWSET_ID) {
                parseOptionsTemplateFlowSet(packet, bodyOffset, flowSetEnd, exporterKey, sourceId);
            } else if (flowSetId >= NetFlowV9Protocol.MIN_DATA_FLOWSET_ID) {
                recordIndex =
                        parseDataFlowSet(
                                packet,
                                bodyOffset,
                                flowSetEnd,
                                flowSetId,
                                exporterIp,
                                exporterKey,
                                receivedAt,
                                headerRecordCount,
                                sysUptimeMillis,
                                unixSeconds,
                                flowSequence,
                                sourceId,
                                exportTime,
                                recordIndex,
                                out);
            }

            offset = flowSetEnd;
        }

        if (offset < end && !NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
            throw new NetFlowV9DecodeException("NetFlow v9 packet has trailing partial FlowSet header");
        }
        return out;
    }

    private void parseTemplateFlowSet(
            ByteBuf packet, int offset, int end, String exporterKey, long sourceId) {
        while (offset < end) {
            if (end - offset < 4) {
                requirePadding(packet, offset, end, "NetFlow v9 template padding");
                return;
            }
            if (NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
                return;
            }
            int templateId = packet.getUnsignedShort(offset);
            int fieldCount = packet.getUnsignedShort(offset + 2);
            if (templateId < NetFlowV9Protocol.MIN_DATA_FLOWSET_ID || fieldCount == 0) {
                throw new NetFlowV9DecodeException("Invalid NetFlow v9 template id/count: " + templateId + "/" + fieldCount);
            }
            int fieldsOffset = offset + 4;
            int fieldsBytes = fieldCount * 4;
            int recordEnd = fieldsOffset + fieldsBytes;
            if (recordEnd > end) {
                throw new NetFlowV9DecodeException("NetFlow v9 template record truncated");
            }

            List<TemplateField> fields = new ArrayList<>(fieldCount);
            for (int fieldOffset = fieldsOffset; fieldOffset < recordEnd; fieldOffset += 4) {
                fields.add(
                        TemplateField.standard(
                                packet.getUnsignedShort(fieldOffset),
                                packet.getUnsignedShort(fieldOffset + 2)));
            }
            templates.put(
                    NetFlowV9Protocol.TEMPLATE_PROTOCOL,
                    exporterKey,
                    sourceId,
                    new TemplateRecord(templateId, fields, false));
            offset = recordEnd;
        }
    }

    private void parseOptionsTemplateFlowSet(
            ByteBuf packet, int offset, int end, String exporterKey, long sourceId) {
        while (offset < end) {
            if (end - offset < 6) {
                requirePadding(packet, offset, end, "NetFlow v9 options template padding");
                return;
            }
            if (NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
                return;
            }
            int templateId = packet.getUnsignedShort(offset);
            int scopeLength = packet.getUnsignedShort(offset + 2);
            int optionLength = packet.getUnsignedShort(offset + 4);
            if (templateId < NetFlowV9Protocol.MIN_DATA_FLOWSET_ID
                    || scopeLength % 4 != 0
                    || optionLength % 4 != 0) {
                throw new NetFlowV9DecodeException("Invalid NetFlow v9 options template");
            }

            int recordEnd = offset + 6 + scopeLength + optionLength;
            if (recordEnd > end) {
                throw new NetFlowV9DecodeException("NetFlow v9 options template record truncated");
            }

            List<TemplateField> fields = new ArrayList<>((scopeLength + optionLength) / 4);
            int fieldOffset = offset + 6;
            int scopeEnd = fieldOffset + scopeLength;
            while (fieldOffset < scopeEnd) {
                fields.add(
                        TemplateField.standard(
                                        packet.getUnsignedShort(fieldOffset),
                                        packet.getUnsignedShort(fieldOffset + 2))
                                .asScope());
                fieldOffset += 4;
            }
            while (fieldOffset < recordEnd) {
                fields.add(
                        TemplateField.standard(
                                packet.getUnsignedShort(fieldOffset),
                                packet.getUnsignedShort(fieldOffset + 2)));
                fieldOffset += 4;
            }

            templates.put(
                    NetFlowV9Protocol.TEMPLATE_PROTOCOL,
                    exporterKey,
                    sourceId,
                    new TemplateRecord(templateId, fields, true));
            offset = recordEnd;
        }
    }

    private int parseDataFlowSet(
            ByteBuf packet,
            int offset,
            int end,
            int templateId,
            String exporterIp,
            String exporterKey,
            Instant receivedAt,
            int headerRecordCount,
            long sysUptimeMillis,
            long unixSeconds,
            long flowSequence,
            long sourceId,
            Instant exportTime,
            int recordIndex,
            List<RawFlowRecord> out) {
        TemplateRecord template =
                templates.get(NetFlowV9Protocol.TEMPLATE_PROTOCOL, exporterKey, sourceId, templateId);
        if (template == null) {
            throw new NetFlowV9DecodeException(
                    "Missing NetFlow v9 template "
                            + templateId
                            + " for exporter "
                            + exporterIp
                            + " sourceId "
                            + sourceId);
        }
        if (template.optionsTemplate()) {
            return recordIndex;
        }
        int recordLength = template.fixedRecordLength();
        if (recordLength <= 0) {
            throw new NetFlowV9DecodeException("Invalid NetFlow v9 data record length for template " + templateId);
        }

        while (offset + recordLength <= end) {
            Map<String, Object> fields =
                    fieldsForRecord(
                            packet,
                            offset,
                            template,
                            recordIndex,
                            headerRecordCount,
                            sysUptimeMillis,
                            unixSeconds,
                            flowSequence,
                            sourceId,
                            exportTime);
            out.add(new RawFlowRecord(NetFlowV9Protocol.SOURCE_TYPE, exporterIp, receivedAt, fields));
            offset += recordLength;
            recordIndex++;
        }
        if (offset < end) {
            requirePadding(packet, offset, end, "NetFlow v9 data FlowSet padding");
        }
        return recordIndex;
    }

    private Map<String, Object> fieldsForRecord(
            ByteBuf packet,
            int offset,
            TemplateRecord template,
            int recordIndex,
            int headerRecordCount,
            long sysUptimeMillis,
            long unixSeconds,
            long flowSequence,
            long sourceId,
            Instant exportTime) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("version", NetFlowV9Protocol.VERSION);
        fields.put("packet_record_count", headerRecordCount);
        fields.put("record_index", recordIndex);
        fields.put("sys_uptime_ms", sysUptimeMillis);
        fields.put("unix_secs", unixSeconds);
        fields.put("export_time", exportTime);
        fields.put("flow_sequence", flowSequence);
        fields.put("source_id", sourceId);
        fields.put("template_id", template.templateId());

        int fieldOffset = offset;
        for (TemplateField field : template.fields()) {
            NetFlowV9Protocol.putField(fields, field, packet, fieldOffset, exportTime, sysUptimeMillis);
            fieldOffset += field.length();
        }
        NetFlowV9Protocol.finishRecord(fields, exportTime, sysUptimeMillis);
        return fields;
    }

    private static void requirePadding(ByteBuf packet, int offset, int end, String label) {
        if (!NetFlowProtocolSupport.allZero(packet, offset, end - offset)) {
            throw new NetFlowV9DecodeException(label + " contains non-zero bytes");
        }
    }
}
