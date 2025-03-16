#!/usr/bin/env python

import os
import pathlib
import sys
import pandas as pd
import matplotlib.pyplot as plt

def process_file(filepath):
    # Read the CSV data into a DataFrame
    df = pd.read_csv(filepath)
    
    # Calculate the required statistics for each column
    stats = df.agg(['mean', 'median', 'std', 'sem']).transpose()
    stats.columns = ['Mean', 'Median', 'Std Dev', 'SEM']
    
    s = ""
    # Print the statistics for each stage
    s += "Statistics for each stage:\n"
    for stage in stats.index:
        s += f"\nStage: {stage}\n"
        s += f"Mean: {stats.loc[stage, 'Mean']:.2f} ns\n"
        s += f"Median: {stats.loc[stage, 'Median']:.2f} ns\n"
        s += f"Standard Deviation: {stats.loc[stage, 'Std Dev']:.2f} ns\n"
        s += f"SEM: {stats.loc[stage, 'SEM']:.2f} ns\n"


    outdir = pathlib.Path(os.getcwd()).joinpath("./out/")
    pathlib.Path.mkdir(outdir, exist_ok=True)

    with open(outdir.joinpath("stats.txt"), "w+") as f:
        _ = f.write(s)

    with open(outdir.joinpath("raw.csv"), "w+") as f:
        with open(filepath) as r:
            _ = f.write(r.read())

    # Create and save the plot
    plt.figure(figsize=(10, 6))
    plt.bar(stats.index, stats['Mean'], yerr=stats['SEM'], capsize=5, color='skyblue')
    plt.ylabel('Execution Time (nanoseconds)')
    plt.title('Execution Time per Stage with SEM Error Bars')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('./out/prof.pdf', bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please provide a filepath to a prof.csv file")
        sys.exit(1)

    process_file(sys.argv[1])

