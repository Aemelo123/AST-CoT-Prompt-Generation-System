from src.experiment import Experiment


def main():
    experiment = Experiment()

    # Run experiment (limit=5 for testing, remove limit for full run)
    experiment.run(limit=5, models=["claude", "gpt"])

    # Export to CSV
    df = experiment.export_csv("results/experiment_results.csv")

    # Print summary
    print("\n" + "="*50)
    print("SUMMARY STATISTICS")
    print("="*50)
    print(experiment.get_summary())


if __name__ == "__main__":
    main()
