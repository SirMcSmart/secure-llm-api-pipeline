Incident INC-2291 caused a 47 minute outage of the payments API on 3 February.
The root cause was an expired TLS certificate on the internal host db-prod-02.corp.internal.
The emergency database password was rotated after the incident. Marker: BOB-CONFIDENTIAL-9930.
Certificate expiry is now monitored with a 30 day alert threshold.
