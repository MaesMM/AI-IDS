snort -c /usr/local/snort/etc/snort/snortml.lua --talos --lua 'snort_ml_engine = { http_param_model = "/usr/local/shared/model.model" }; snort_ml = {}; trace = { modules = { snort_ml = {all = 1} } };' -r /usr/local/shared/simulated_sql_injectionAI.pcap --daq-dir /usr/local/lib/daq_s3/lib/daq
snort -c /usr/local/snort/etc/snort/snortml.lua -r /usr/local/shared/simulated_sql_injectionAI.pcap --daq-dir /usr/local/lib/daq_s3/lib/daq


snort -c /usr/local/snort/etc/snort/snort.lua -r /usr/local/shared/simulated_sql_injectionAI.pcap --daq-dir /usr/local/lib/daq_s3/lib/daq | grep alert