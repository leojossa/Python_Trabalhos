import streamlit as st
import pandas as pd

@st.cache
def load_data():
    file = 'http://data.insideairbnb.com/spain/catalonia/barcelona/2020-05-11/visualisations/listings.csv'
    columns = {'latitude': 'lat', 'longitude': 'lon'}
    df = pd.read_csv(file)
    df = df.rename(columns=columns)
    return df

df = load_data()

st.title('Airbnb em Barcelona')
st.markdown(
    """
    Dashboard para analise de locacoes através do Airbnb em Barcelona
    """
)

st.sidebar.header('Configuracoes')
if st.sidebar.checkbox('Mostrar tabela'):
    st.markdown('### Tabela de Dados')
    st.write(df)

price = st.sidebar.slider('Veja os imoveis pelo valor de locacao', 0, 192, 100)

room_types = df.room_type.unique()
room_types_selected = st.sidebar.multiselect('Selecione o tipo de locacao', room_types)

if not room_types_selected:
    room_types_selected = df.room_type.unique()

st.map(df[(df['price'] == price) & (df['room_type'].isin(room_types_selected))])

#para iniciar o servidor digite streamlit run airbnb.py no terminal
