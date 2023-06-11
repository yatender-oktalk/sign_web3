# NIF for Elixir.EWeb3

## To build the NIF module:

- Your NIF will now build along with your project.

## To load the NIF:

```elixir
defmodule CWeb3 do
    use Rustler, otp_app: :c_web3, crate: "web3"

    # When your NIF is loaded, it will override this function.
    def add(_a, _b), do: :erlang.nif_error(:nif_not_loaded)
end
```

### Setup 

```elixir
config :ethereumex,
  url: "http://localhost:8545"
```

or just give url where chain is running 
if using infura then give
```elixir
config :ethereumex,
  url: "https://goerli.infura.io/v3/{API_KEY}"
```


### Running the ABI

```elixir
defmodule EthComm.Contracts.Contract do
  use Ethers.Contract, abi_file: "{abi_location}.json",
  default_address: "smart_contract_address"
end
```

## Examples

[This](https://github.com/hansihe/NifIo) is a complete example of a NIF written in Rust.
