import streamlit as st

st.set_page_config(page_title="Attack Graph Generator", page_icon="🛡️")

st.title("🛡️ Attack Graph Generator")

st.write("Web application is working!")

network = st.text_input("Enter Network", placeholder="Example: 192.168.1.0/24")

if st.button("Start Scan"):
    if network:
        st.success(f"Network entered: {network}")
    else:
        st.error("Please enter a network.")
