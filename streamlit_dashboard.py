import streamlit as st
import json
import os
from pathlib import Path

# Page setup
st.set_page_config(page_title='Scan Dashboard', layout='wide')
st.title('Scan Results Dashboard')

# File uploader
uploaded = st.file_uploader(
    'Upload a ZAP alerts JSON (zap_alerts.json) or nikto.txt file',
    accept_multiple_files=True
)

alerts = []

for f in uploaded:
    name = f.name.lower()
    data = f.read().decode('utf-8', errors='ignore')

    # Parse ZAP JSON alerts
    if ('zap' in name and name.endswith('.json')) or name.endswith('zap_alerts.json'):
        try:
            # attempt JSON parse (handle both list and dict)
            parsed = json.loads(data.replace("'", '"'))
            if isinstance(parsed, dict) and 'alerts' in parsed:
                alerts.extend(parsed['alerts'])
            elif isinstance(parsed, list):
                alerts.extend(parsed)
            else:
                st.warning(f"{f.name}: JSON parsed but no recognizable alert structure.")
        except Exception as e:
            st.error(f"{f.name}: Failed to parse JSON — {e}")

    # Display Nikto text output
    elif 'nikto' in name or name.endswith('.txt'):
        st.subheader(f' Nikto Output Preview — {f.name}')
        st.text(data[:5000])  # preview first 5000 chars

# Display ZAP Alerts (if any)
if alerts:
    st.subheader(' ZAP Alerts Summary')
    for a in alerts:
        alert_name = a.get('alert', '-')
        risk = a.get('risk', '-')
        url = a.get('url', '-')
        param = a.get('param', '-')
        desc = a.get('other', '')[:400]

        st.markdown(f"**{alert_name}** — *{risk}*")
        st.write(f"**URL:** {url}")
        if param and param != '-':
            st.write(f"**Parameter:** {param}")
        if desc:
            st.write(f"**Description:** {desc}")
        st.markdown("---")

else:
    st.info(" Upload a ZAP `zap_alerts.json` or Nikto `.txt` file to view results.")

st.caption("Tip: export ZAP alerts as JSON from the ZAP UI or use zap_alerts.json produced by your automated pipeline.")

