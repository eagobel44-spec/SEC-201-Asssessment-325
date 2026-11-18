# protect.py
# This is where the dataset is protected, and it happens on the client before anything
# is sent to the server (lecture 8). It also decrypts the encrypted columns again for a
# team member that has the team keys.

import crypto

# ---------- what happens to each column ----------

# These columns are removed completely and never sent (personal information that is not
# needed, like the full name, company and location of the publisher).
# The label is removed too, since that is the answer and the server should not get it.
REMOVE = ["real_name", "company", "location", "github_created", "label", "label_source"]

# The two main identifiers (package name and publisher) are turned into pseudonyms with hmac.
PSEUDONYM = ["package", "publisher"]

# These columns are encrypted with aes-gcm with the team column key (columns that identify
# the package or a person, which teammates need to read but the server does not).
ENCRYPT = ["package", "publisher", "tarball", "shasum", "integrity", "git_head",
           "repository", "maintainers", "github_url", "install_script_text", "deps_added"]

# These columns are changed from an exact number into a range (like 100-999).
RANGE = ["followers", "public_repos", "n_packages"]

# These columns become True/False (was there a value or not).
BOOLEAN = ["attestations", "npm_signature"]

# Any other column (version, published, the True/False flags...) is left readable,
# because the server uses those to score the row.


# Changes an exact number into a range, so 420 becomes "100-999" and 7 becomes "1-9".
# If there is no number, it becomes "unknown".
def to_range(value):
    try:
        number = int(float(value))
    except ValueError:
        return "unknown"
    if number <= 0:
        return "0"
    low = 10 ** (len(str(number)) - 1)
    return f"{low}-{low * 10 - 1}"


# Takes one row of the dataset and gives back the protected row.
# The team keys are used here: the hmac key for the pseudonyms and the column key for
# the aes-gcm encrypted columns.
def protect_row(row, hmac_key, column_key):
    protected = {}

    # The row id is an hmac of the package and version, so the row has a unique id
    # without showing which package it is.
    protected["row_id"] = crypto.pseudonym(hmac_key, row["package"] + "@" + row["version"])

    for column, value in row.items():
        if column in REMOVE:
            continue
        # The package name and publisher get both: a pseudonym (can't be reversed) and an
        # encrypted copy (so that a team member can still read the real name).
        if column in PSEUDONYM:
            protected[column + "_pseudonym"] = crypto.pseudonym(hmac_key, value)
        if column in ENCRYPT:
            protected[column + "_encrypted"] = crypto.aes_encrypt(column_key, value.encode("utf-8"))
        elif column in RANGE:
            protected[column + "_range"] = to_range(value)
        elif column in BOOLEAN:
            protected["has_" + column] = str(value != "")
        else:
            protected[column] = value
    return protected


# The team member decrypts the encrypted columns using the team column key.
# The pseudonyms are left alone, since those can't be decrypted.
def unprotect_row(protected, column_key):
    row = {}
    for column, value in protected.items():
        if column.endswith("_encrypted"):
            name = column[: -len("_encrypted")]
            row[name] = crypto.aes_decrypt(column_key, value).decode("utf-8")
        else:
            row[column] = value
    return row
