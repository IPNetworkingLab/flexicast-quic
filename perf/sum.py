import pandas as pd
import sys

df = pd.read_csv(sys.argv[1], delim_whitespace=True, header=None, names=["index","time","bytes"])
total = df["bytes"].sum()
print("RESULT-BYTES",total)
diff = df["time"].max() - df["time"].min()
print("RESULT-CLIENTGP", total*1000000 / diff )
if total <= 1:
    sys.exit(1)
