import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("data.csv")
data.plot.hist(y=['options','contents'], alpha=0.8, bins=20)
plt.show()