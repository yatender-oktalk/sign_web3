defmodule SignWeb3 do
  @moduledoc """
  Documentation for `SignWeb3`.
  """

  @type hash :: String.t()

  use Rustler, otp_app: :sign_web3, crate: "web3"
  def gen_keys(), do: :erlang.nif_error(:nif_not_loaded)
  def sign_tx(_sk, _tx, _chain_id \\ 1), do: :erlang.nif_error(:nif_not_loaded)
  def encode_call(_call), do: :erlang.nif_error(:nif_not_loaded)
  def decode_result(_result, _type), do: :erlang.nif_error(:nif_not_loaded)
  def to_addr(_sk), do: :erlang.nif_error(:nif_not_loaded)

  def get_transaction_by_hash(hash), do: send_tx("eth_getTransactionByHash", [hash])

  def send_raw(tx), do: send_tx("send_txRawTransaction", ["0x#{tx}}"])
  def gas_price, do: send_tx("eth_gasPrice", [])
  def get_tx_count(address), do: send_tx("eth_getTransactionCount", [address, "latest"])
  def get_balance(address), do: send_tx("eth_getBalance", [address, "latest"]) |> parse_balance()

  def parse_balance(%{"result" => result}) do
    result |> String.replace_prefix("0x","") |> Integer.parse(16) |> elem(0)
  end

  def decode(num) do
    num
    |> String.slice(2..-1)
    |> Base.decode16!(case: :lower)
    |> :binary.decode_unsigned
  end

  @spec send_tx(String.t(), list(binary())) :: map() | nil | {:error, any()}
  def send_tx(method, params) do
    url()
    |> Tesla.post(
      %{
        "id" => 1,
        "jsonrpc" => "2.0",
        "method" => method,
        "params" => params
      } |> Jason.encode!(), [{"Accept", "application/json"}]
    )
    |> case do
        {:ok, %Tesla.Env{body: body} } ->
          Jason.decode!(body)
        error ->
          error
      end
  end

  defp url do
    Application.fetch_env!(:sign_web3, :blockchain_url)
  end
end
