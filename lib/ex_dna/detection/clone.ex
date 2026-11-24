defmodule ExDNA.Detection.Clone do
  @moduledoc """
  Represents a detected code clone — a group of structurally identical fragments.
  """

  @type fragment_location :: %{
          file: String.t(),
          line: pos_integer(),
          ast: Macro.t(),
          mass: pos_integer()
        }

  @type clone_type :: :type_i | :type_ii | :type_iii

  @type t :: %__MODULE__{
          type: clone_type(),
          hash: binary() | nil,
          mass: pos_integer(),
          fragments: [fragment_location()],
          source_snippets: [String.t()],
          suggestion: map() | nil,
          behaviour_suggestion: map() | nil,
          similarity: float() | nil
        }

  defstruct [
    :type,
    :hash,
    :mass,
    :suggestion,
    :behaviour_suggestion,
    :similarity,
    fragments: [],
    source_snippets: []
  ]

  @doc """
  Build a clone from a group of matching fragments.

  Source snippets are left empty; call `put_snippets/1` once the clone is known
  to survive filtering, since rendering them is the costly part.
  """
  @spec from_fragments([map()], clone_type()) :: t()
  def from_fragments(frags, type) do
    mass = frags |> List.first() |> Map.get(:mass, 0)

    locations =
      Enum.map(frags, fn f ->
        %{file: f.file, line: f.line, ast: f.ast, mass: f.mass}
      end)

    %__MODULE__{
      type: type,
      hash: List.first(frags).hash,
      mass: mass,
      fragments: locations
    }
  end

  @doc """
  Render source snippets for a clone that has none yet.
  """
  @spec put_snippets(t()) :: t()
  def put_snippets(%__MODULE__{source_snippets: [], fragments: frags} = clone) do
    snippets = Enum.map(frags, fn f -> f.ast |> unwrap_grouped_def() |> safe_to_string() end)
    %{clone | source_snippets: snippets}
  end

  def put_snippets(clone), do: clone

  defp safe_to_string(ast) do
    Macro.to_string(ast)
  rescue
    _ -> inspect(ast)
  end

  defp unwrap_grouped_def(ast) do
    Macro.prewalk(ast, fn
      {:__ex_dna_grouped_def__, _meta, clauses} -> {:__block__, [], clauses}
      node -> node
    end)
  end
end
