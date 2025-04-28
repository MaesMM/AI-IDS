FROM ciscotalos/snort3:latest AS snort

# Switch to root user to install wget and download the rules
USER root

ADD https://www.snort.org/downloads/community/snort3-community-rules.tar.gz .

RUN tar -xvzf ./snort3-community-rules.tar.gz  
    

RUN sed -i 's/include \$RULE_PATH/# include \$RULE_PATH/' /etc/snort/snort.conf 
    
RUN cd snort3-community-rules && \
    cp * /etc/snort/rules && \
    echo "include /etc/snort/rules/snort3-community.rules" >> /etc/snort/snort.conf && \
    sed -i 's/WHITE_LIST_PATH \.\.\/rules/WHITE_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf && \
    sed -i 's/BLACK_LIST_PATH \.\.\/rules/BLACK_LIST_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf && \
    sed -i -e '0,/\# output unified2/{//i\output unified2: filename snort.u2, limit 50' -e '}' /etc/snort/snort.conf

# Switch back to the original user
USER snorty
