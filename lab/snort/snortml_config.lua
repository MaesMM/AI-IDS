-- snortml_config.lua

snortml = 
{
    -- Path to your converted model
    model_path = '/usr/local/snort/etc/snort/models/ids_rf_model.onnx',
    
    -- Define feature extraction mapping (maps Snort packet fields to your model features)
    feature_mapping = {
        ["Destination Port"] = "ip_dst_port",
        ["Flow Duration"] = "stream_session.session_time",
        ["Total Fwd Packets"] = "flow.forward_packets",
        ["Total Backward Packets"] = "flow.backward_packets",
        ["Total Length of Fwd Packets"] = "flow.forward_bytes",
        ["Total Length of Bwd Packets"] = "flow.backward_bytes",
        ["Fwd Packet Length Max"] = "custom.fwd_packet_length_max",
        ["Fwd Packet Length Min"] = "custom.fwd_packet_length_min",
        ["Fwd Packet Length Mean"] = "custom.fwd_packet_length_mean",
        -- Add other required mappings
    },
    
    -- Add custom feature calculation functions
    feature_functions = {
        ["custom.fwd_packet_length_max"] = function(p)
            -- Custom Lua function to calculate max forward packet length
            -- This is just an example - actual implementation will be more complex
            return 1500  -- Placeholder value
        end,
        ["custom.fwd_packet_length_min"] = function(p)
            return 40  -- Placeholder value
        end,
        ["custom.fwd_packet_length_mean"] = function(p)
            return 300  -- Placeholder value
        end
        -- Add more custom calculation functions
    }, -- ADDED COMMA HERE
    
    -- Detection threshold (adjust based on your model's performance)
    threshold = 0.75,
    
    -- Class labels (must match your label_encoder)
    class_labels = {
        "BENIGN",
        "PortScan"
    },
    
    -- Performance settings
    batch_size = 64,
    inference_interval = 5,
    
    -- Logging settings
    log_predictions = true
}
