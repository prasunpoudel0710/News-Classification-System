import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

nltk.download('stopwords')
nltk.download('punkt')


def clean_text(text):
    text = text.lower().replace('\n', ' ').replace('\r', '').strip()  # lower case and new line and carriage return
    print(text)
    text = re.sub(' +', ' ', text)
    print(text)
    text = re.sub(r'[^\w\s]', '', text)
    print(text)

    stop_words = set(stopwords.words('english'))
    word_tokens = word_tokenize(text)
    filtered_sentence = [w for w in word_tokens if w not in stop_words]

    text = " ".join(filtered_sentence)
    return text


text1 = "This is a sample text with lots of noise and unnecessary characters. It contains typos, extra white spaces and symbols like @#$%. There are also some digits like 1234 mixed in. This text needs to be cleaned before it can be used for analysis or processing."
print(clean_text(text1))
