import os

from collectors.npm_collector import get_dataframe
from collectors.github_collector import collect_publishers
from cleaning.age_cleaner import clean_by_age
from synthetic import generate as synthetic

# True:  use the synthetic packages (imitations of attacks, no real malware,
#        nothing downloaded).
# False: use the real npm packages, including ones with known malicious
#        releases.
USE_SYNTHETIC = True

# Everything this program reads and writes (cache/, outputs/) is next to
# this file, so work from this folder no matter where it was started from.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Collected and cleaned results for each kind of data go in their own folder.
OUTPUT_DIR = os.path.join("outputs", "synthetic" if USE_SYNTHETIC else "original")

if __name__ == "__main__":
    if USE_SYNTHETIC:
        df = get_dataframe(synthetic.package_names())
        # Made-up publisher profiles, no GitHub request is made.
        publishers = synthetic.collect_publishers(df)
    else:
        df = get_dataframe()
        publishers = collect_publishers(df)

    # Add each publisher's GitHub info to every package row in df.
    df = df.merge(publishers, on="publisher", how="left")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    publishers.to_csv(os.path.join(OUTPUT_DIR, "github_publishers.csv"), index=False)
    df.to_csv(os.path.join(OUTPUT_DIR, "npm_versions_with_publishers.csv"), index=False)

    # The cleaned data is saved as its own file; df itself stays unfiltered.
    clean_df = clean_by_age(df)
    clean_df.to_csv(os.path.join(OUTPUT_DIR, "npm_versions_clean.csv"), index=False)

    print(f"{len(df)} versions of {df['package'].nunique()} packages")
    print(df["label"].value_counts().to_string())
    print(f"Saved to make_dataset/{OUTPUT_DIR.replace(os.sep, '/')}/")
