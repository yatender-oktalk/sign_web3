defmodule SignWeb3.MixProject do
  use Mix.Project

  def project do
    [
      app: :sign_web3,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.26.0"},
      {:tesla, "~> 1.4.0"},
      {:hackney, "~> 1.17.0"},
      {:ethers, "~> 0.0.3"},
      {:ethereumex, "~> 0.10"},
      {:ex_abi, "~> 0.6.0"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
