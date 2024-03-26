import pandas as ps
import wget
import zipfile
from tqdm import tqdm
from features import extract_features
from os.path import exists
from multiprocessing import Pool, freeze_support

def gen_dataframe(desc, count, req_df, label):
    # feature count = 9
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
        # Label 1 if phishing else 0
        "Label",
    ]
    ft = []
    for i in tqdm(range(count), desc=f"getting {desc} data ... "):
        ft.append(extract_features(req_df["url"][i]) + [label])
    print(f"{desc} Data Fetching completed.")
    return ps.DataFrame(ft, columns=ft_title)


def main():
    # Dataset from https://www.unb.ca/cic/datasets/url-2016.html
    if not (exists("legit.csv") and exists("phishing.csv")):
        print("Error fetching dataset : \n", err)
        exit()

    ph_df = ps.read_csv("phishing.csv", header=None, names=["url"])
    lg_df = ps.read_csv("legit.csv", header=None, names=["url"])
    # data count
    count = 6000
    # Create Result dataset
    seed = 20
    #  get n=count phishing url and reset index
    req_ph = ph_df.sample(n=count, random_state=seed).reset_index(drop=True)
    #  get n=count legit url and reset indes
    req_lg = lg_df.sample(n=count, random_state=seed).reset_index(drop=True)

    # Adding features
    legit_label = 0
    phishing_label = 1
    # Parallelizing Process
    with Pool(2) as p:
        res = p.starmap(
            gen_dataframe,
            [
                ("legit", count, req_lg, legit_label),
                ("phishing", count, req_ph, phishing_label),
            ],
        )

    [lg_final, ph_final] = res
    # print(ph_final)
    # print(lg_final)
    print("writing phishing data to csv ")
    ph_final.to_csv("phish_final.csv", index=False)
    print("writing legit data to csv ")
    lg_final.to_csv("legit_final.csv", index=False)


if __name__ == "__main__":
    freeze_support()
    main()
