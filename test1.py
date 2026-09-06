import streamlit as st

# ==========================================
# YOUR BACKEND CODE (Refactored to return values)
# ==========================================


def ulta(decimal_num):
    # Special case for 0
    if decimal_num == 0:
        return "0"

    bit = decimal_num
    v = ""
    x = ""
    y = bit  # Set y to starting number to avoid string comparison bugs

    while y != 0 and y != 1:
        v = bit % 2
        y = bit // 2
        bit = y
        x = x + str(v)

    if y == 1:
        x = x + "1"

    j = x[::-1]
    return j


def binary(binary_str):
    l = []
    for i in binary_str:
        j = int(i)
        if j in [0,1]:
            l.append(j)
        else:
            print("INVALID DIGIT USED..")   


    m = 0
    for k in range(len(l), 0, -1):
        m += 2 ** (k - 1) * l[len(l) - k]

    return m


# ==========================================
# FRONTEND (Streamlit Web Interface)
# ==========================================

st.set_page_config(
    page_title="Decimal-Binary Converter", page_icon="🔢", layout="centered"
)

# Header banner matching your original terminal intro
st.title("🔢 DECIMAL ↔ BINARY CONVERTER")
st.caption("==================================================")

# Dropdown / Select box for user choice
choice = st.selectbox(
    "Select the type of conversion you would like to do:",
    (
        "Select an option...",
        "1: Decimal to Binary (ulta)",
        "2: Binary to Decimal (binary)",
    ),
)

st.divider()

# Option 1: Decimal to Binary
if choice == "1: Decimal to Binary (ulta)":
    st.subheader("Decimal ➡️ Binary")
    dec_input = st.number_input(
        "ENTER A DECIMAL NUMBER:", min_value=0, step=1, value=10
    )

    if st.button("Convert", type="primary"):
        result = ulta(int(dec_input))
        st.success(f"**Binary Output:** `{result}`")

# Option 2: Binary to Decimal
elif choice == "2: Binary to Decimal (binary)":
    st.subheader("Binary ➡️ Decimal")
    bin_input = st.text_input("ENTER A BINARY NUMBER:", value="1010")

    if st.button("Convert", type="primary"):
        # Quick safety check to ensure user only entered 0s and 1s
        if all(char in "01" for char in bin_input) and len(bin_input) > 0:
            result = binary(bin_input)
            st.success(f"**Decimal Output:** `{result}`")
        else:
            st.error("Please enter a valid binary number containing only 0s and 1s.")