import pickle
import pandas as pd
from features import extract_features

# info : https://phishtank.org/phish_detail.php?phish_id=8043169

# url = "https://form-solicltatu.extra-cash2023aprobado.top/"
url = "http://nittendostorecolombia.liveblog365.com/?i=1"

features = extract_features(url)
# feature count = 9
# Igonre Label : )
ft_title = [
    "IP",
    "Len",
    "Multiple //",
    "Symbols",
    "https",
    "history",
    "iframe",
    "mouseover",
    "domainAge",
]
with open("mlp_model.pkl", "rb") as mod_file:
    model = pickle.load(mod_file)

test = pd.DataFrame(data=[features], columns=ft_title)
print(f"\nurl: {url}\n")
print(test, "\n")
res = model.predict(test)
if res[0] == 0:
    print("The site is legit\n")
else:
    print("The site is phishing site\n")
