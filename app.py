# app.py - Full Crypto Performance Lab with UI Enhancements

import streamlit as st
import pandas as pd
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import plotly.express as px
from streamlit_lottie import st_lottie
import requests

# use string source for graphviz_chart
dot_source = """
digraph {
    S -> A -> B -> C -> N -> R -> D -> E
}
"""
st.graphviz_chart(dot_source)

# Page config
st.set_page_config(page_title="Crypto Performance Lab", layout="wide", page_icon="🔐")

# Lottie animation
lottie_url = "https://assets5.lottiefiles.com/packages/lf20_w51pcehl.json"
try:
    lottie_json = requests.get(lottie_url).json()
    st_lottie(lottie_json, height=180, key="crypto_lottie")
except:
    st.warning("⚠️ Could not load animation.")

st.markdown("<h1 style='text-align: center; color: gold;'>🔐 Crypto Performance Lab</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Benchmark RSA & AES, manage keys, simulate message flow, and compare security methods.</p><hr>", unsafe_allow_html=True)

# ------------------------- Helper encryption functions -------------------------

# ... (unchanged code for rsa_encrypt_decrypt, aes_encrypt_decrypt, hybrid_encrypt_decrypt_simulation here)

def rsa_encrypt_decrypt(message, key_size=2048):
    key = RSA.generate(key_size)
    public_key = key.publickey()
    encryptor = PKCS1_OAEP.new(public_key)
    decryptor = PKCS1_OAEP.new(key)
    message_bytes = message.encode()

    start_enc = time.time()
    ciphertext = encryptor.encrypt(message_bytes)
    end_enc = time.time()

    start_dec = time.time()
    decrypted_message = decryptor.decrypt(ciphertext).decode()
    end_dec = time.time()

    return {
        'Method': f'RSA-{key_size}',
        'Encrypt Time (s)': end_enc - start_enc,
        'Decrypt Time (s)': end_dec - start_dec,
        'Match': message == decrypted_message,
        'Message': message
    }

def aes_encrypt_decrypt(message, key_bits=128):
    key = get_random_bytes(key_bits // 8)
    cipher = AES.new(key, AES.MODE_EAX)
    msg_bytes = message.encode()

    start_enc = time.time()
    ciphertext, tag = cipher.encrypt_and_digest(msg_bytes)
    end_enc = time.time()

    start_dec = time.time()
    cipher_dec = AES.new(key, AES.MODE_EAX, cipher.nonce)
    decrypted = cipher_dec.decrypt(ciphertext).decode()
    end_dec = time.time()

    return {
        'Method': f'AES-{key_bits}',
        'Encrypt Time (s)': end_enc - start_enc,
        'Decrypt Time (s)': end_dec - start_dec,
        'Match': message == decrypted,
        'Message': message
    }

def hybrid_encrypt_decrypt_simulation(message, rsa_key_size=2048, aes_key_bits=128):
    rsa_key = RSA.generate(rsa_key_size)
    public_key = rsa_key.publickey()

    start_h_enc = time.time()
    aes_key = get_random_bytes(aes_key_bits // 8)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())

    rsa_enc = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_enc.encrypt(aes_key)
    end_h_enc = time.time()

    start_h_dec = time.time()
    rsa_dec = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = rsa_dec.decrypt(encrypted_aes_key)

    aes_dec = AES.new(decrypted_aes_key, AES.MODE_EAX, aes_cipher.nonce)
    decrypted_message = aes_dec.decrypt(ciphertext).decode()
    end_h_dec = time.time()

    return {
        'Method': f'Hybrid-AES{aes_key_bits}+RSA{rsa_key_size}',
        'Encrypt Time (s)': end_h_enc - start_h_enc,
        'Decrypt Time (s)': end_h_dec - start_h_dec,
        'Match': message == decrypted_message,
        'Message': message
    }

# ------------------------- Tabs -------------------------
tab1, tab2, tab3, tab4 = st.tabs(["🧪 Benchmark", "📈 Visualization", "🗝️ Key Manager", "📡 Message Flow & Comparison"])

# ------------------------- Tab 1: Benchmark -------------------------
with tab1:
    st.header("🧪 Encryption Benchmark")
    bench_msg = st.text_area("Enter a message to benchmark", value="Hello Crypto World!")

    rsa_sizes = st.multiselect("Select RSA key sizes (bits)", options=[1024, 2048, 4096], default=[1024, 2048])
    run_bench = st.button("🔍 Run Benchmark")

    if run_bench:
        results = []
        for ks in rsa_sizes:
            with st.spinner(f"Testing RSA-{ks}..."):
                results.append(rsa_encrypt_decrypt(bench_msg, key_size=ks))
        with st.spinner("Testing AES-128..."):
            results.append(aes_encrypt_decrypt(bench_msg, key_bits=128))

        df = pd.DataFrame(results)
        st.session_state['benchmark_df'] = df

        st.success("✅ Benchmark Completed")
        st.dataframe(df)

        col1, col2 = st.columns(2)
        col1.metric("🔢 Total Tests", len(df))
        col2.metric("⚡ Fastest Encrypt", df.loc[df['Encrypt Time (s)'].idxmin()]['Method'])

        st.download_button("⬇️ Download benchmark CSV", df.to_csv(index=False).encode(), "benchmark.csv", "text/csv")

# ------------------------- Tab 2: Visualization -------------------------
with tab2:
    st.header("📈 Visualization")
    if 'benchmark_df' in st.session_state:
        dfv = st.session_state['benchmark_df'].copy()

        st.subheader("Encryption and Decryption Times")
        fig1 = px.bar(dfv, x='Method', y=['Encrypt Time (s)', 'Decrypt Time (s)'], barmode='group')
        st.plotly_chart(fig1, use_container_width=True)

        st.subheader("Match Results")
        st.table(dfv[['Method', 'Match']])
    else:
        st.info("Run a benchmark in the Benchmark tab first.")

# ------------------------- Tab 3: Key Manager (unchanged logic, better UI) -------------------------
with tab3:
    st.header("🗝️ RSA Key Manager")
    gen_size = st.selectbox("Choose RSA Key Size", [1024, 2048, 4096], index=1)

    if st.button("🔑 Generate Key Pair"):
        with st.spinner("Generating RSA keypair..."):
            private_key = RSA.generate(gen_size)
            public_key = private_key.publickey()
            st.session_state['private_key'] = private_key
            st.session_state['public_key'] = public_key
            st.success("✅ RSA key pair generated")

    if 'private_key' in st.session_state:
        st.subheader("🔐 Private Key")
        st.code(st.session_state['private_key'].export_key().decode(), language="text")
        st.subheader("🔓 Public Key")
        st.code(st.session_state['public_key'].export_key().decode(), language="text")

        st.markdown("---")
        st.subheader("🔁 Encrypt & Decrypt")
        km_msg = st.text_area("Enter a message:", "")
        if st.button("🔁 Encrypt & Decrypt Message"):
            pub = st.session_state['public_key']
            priv = st.session_state['private_key']
            enc_cipher = PKCS1_OAEP.new(pub)
            ciphertext = enc_cipher.encrypt(km_msg.encode())
            dec_cipher = PKCS1_OAEP.new(priv)
            plaintext = dec_cipher.decrypt(ciphertext).decode()

            st.write("🔒 Encrypted (hex):")
            st.code(ciphertext.hex())
            st.write("🔓 Decrypted message:")
            st.code(plaintext)
            st.success("Match: " + str(plaintext == km_msg))

# ------------------------- Tab 4: Message Flow & Comparison (unchanged logic, enhanced layout) -------------------------
with tab4:
    st.header("📡 Message Flow & Comparison")
    st.write("Visualize the hybrid encryption message flow and compare performance of RSA, AES, and Hybrid methods.")

    # Flow Diagram
    dot = graphviz.Digraph()
    dot.node("S", "Sender")
    dot.node("A", "Generate AES key")
    dot.node("B", "Encrypt message with AES")
    dot.node("C", "Encrypt AES key with Receiver's RSA public key")
    dot.node("N", "Network (transmit data)")
    dot.node("R", "Receiver")
    dot.node("D", "Decrypt AES key with RSA private key")
    dot.node("E", "Decrypt message with AES")
    dot.edges(["SA", "AB", "BC", "CN", "NR", "RD", "DE"])
    st.graphviz_chart(dot)

    st.markdown("### 🧭 Step-by-step Simulation")
    if 'flow_step' not in st.session_state:
        st.session_state['flow_step'] = 0

    flow_steps = [
        ("Generate RSA key pair (Receiver)", "Receiver generates RSA keypair (public/private)."),
        ("Sender: generate AES session key", "Sender creates a fresh AES session key for this message."),
        ("Sender: encrypt message with AES", "Sender encrypts the actual message using AES (fast)."),
        ("Sender: encrypt AES key with RSA public key", "Sender encrypts the AES session key with Receiver's RSA public key (secure)."),
        ("Transmit encrypted message+key", "Network transmits ciphertext and RSA-encrypted AES key."),
        ("Receiver: decrypt AES key with RSA private key", "Receiver uses RSA private key to decrypt AES key."),
        ("Receiver: decrypt message with AES", "Receiver uses AES key to decrypt the message.")
    ]

    if st.button("▶️ Next Step"):
        idx = st.session_state['flow_step']
        if idx < len(flow_steps):
            st.info(f"Step {idx+1}: **{flow_steps[idx][0]}**")
            st.write(flow_steps[idx][1])
            st.session_state['flow_step'] += 1
        else:
            st.success("✅ Process Completed! Restart to simulate again.")

    if st.button("🔁 Restart Flow"):
        st.session_state['flow_step'] = 0

    st.markdown("---")
    st.header("📊 Performance Comparison: RSA vs AES vs Hybrid")
    cmp_msg = st.text_input("Enter message for comparison", value="Performance comparison message")

    if st.button("🔍 Compare Performance"):
        with st.spinner("Running RSA test..."):
            r_res = rsa_encrypt_decrypt(cmp_msg, key_size=2048)
        with st.spinner("Running AES test..."):
            a_res = aes_encrypt_decrypt(cmp_msg, key_bits=128)
        with st.spinner("Running Hybrid simulation..."):
            h_res = hybrid_encrypt_decrypt_simulation(cmp_msg, rsa_key_size=2048, aes_key_bits=128)

        cmp_df = pd.DataFrame([r_res, a_res, h_res])
        st.subheader("Comparison Table")
        st.dataframe(cmp_df[['Method', 'Encrypt Time (s)', 'Decrypt Time (s)', 'Match']])

        st.subheader("Comparison Chart")
        cmp_long = cmp_df.melt(id_vars=['Method'], value_vars=['Encrypt Time (s)', 'Decrypt Time (s)'], var_name='Operation', value_name='Time (s)')
        fig_cmp = px.bar(cmp_long, x='Method', y='Time (s)', color='Operation', barmode='group')
        st.plotly_chart(fig_cmp, use_container_width=True)

        st.download_button("⬇️ Download Comparison CSV", cmp_df.to_csv(index=False).encode(), "comparison.csv", "text/csv")
