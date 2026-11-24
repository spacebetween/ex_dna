defmodule ExDNA.AST.Fingerprint do
  @moduledoc """
  Computes structural fingerprints (hashes) for AST subtrees.

  Every subtree whose *mass* (node count) meets the threshold is hashed.
  Two normalized ASTs with the same hash are structurally identical clones.

  Each fragment also carries a set of lightweight sub-hashes from its child
  subtrees, computed during the same walk, for efficient Jaccard-based
  fuzzy candidate pruning in `ExDNA.Detection.Fuzzy`.

  Sliding windows over sibling sequences in module bodies are fingerprinted
  to catch clones that span multiple adjacent statements.
  """

  alias ExDNA.AST.{Location, Normalizer}

  @type hash :: binary()
  @type fragment :: %{
          hash: hash(),
          mass: pos_integer(),
          ast: Macro.t(),
          file: String.t(),
          line: pos_integer(),
          sub_hashes: MapSet.t(integer())
        }

  # Minimum AST mass for a sub-node to contribute a sub-hash.
  # Nodes below this (single calls, variables) are too common to discriminate.
  @sub_hash_min_mass 5
  @module_level_forms [:def, :defp, :defmacro, :defmacrop]

  @doc """
  Walk an AST and return all subtree fragments that meet `min_mass`.

  Pass `sub_hashes: false` when fuzzy detection is off; fragments then carry an
  empty `sub_hashes` set.
  """
  @spec fragments(Macro.t(), String.t(), pos_integer(), keyword()) :: [fragment()]
  def fragments(ast, file, min_mass, opts \\ []) do
    ctx = %{
      file: file,
      min_mass: min_mass,
      norm_opts: Keyword.take(opts, [:literal_mode, :normalize_pipes, :normalize_variables]),
      excluded: Keyword.get(opts, :excluded_macros, []) |> MapSet.new(),
      ignored_attrs: Keyword.get(opts, :ignored_attributes, []) |> MapSet.new(),
      max_window_size: Keyword.get(opts, :max_window_size, 4),
      max_module_forms: Keyword.get(opts, :max_module_forms, 200),
      sub_hashes: Keyword.get(opts, :sub_hashes, true)
    }

    {frags, _sub_hashes, _mass, _line} = walk(ast, ctx, [])
    frags
  end

  # Each walk clause returns {fragments, sub_hashes, mass, min_line} for its subtree,
  # so mass and start line are computed once per node rather than once per ancestor.

  # __block__ — walk children, track per-child info for window construction
  defp walk({:__block__, meta, args}, ctx, acc) when is_list(args) do
    {acc, per_child, all_subs, mass, line} =
      Enum.reduce(args, {acc, [], MapSet.new(), 1, meta_line(meta)}, fn child,
                                                                        {a, per_child, all, m, l} ->
        {a, child_s, child_m, child_l} = walk(child, ctx, a)

        {a, [{child_s, child_m, child_l} | per_child], MapSet.union(all, child_s), m + child_m,
         min_line(l, child_l)}
      end)

    acc =
      if module_body?(args, ctx) do
        sibling_windows(args, Enum.reverse(per_child), ctx, acc)
      else
        acc
      end

    {acc, all_subs, mass, line}
  end

  # Module attribute (@attr value) — skip ignored attributes, fingerprint the rest
  defp walk({:@, _meta, [{attr_name, _, _}]} = node, ctx, acc) when is_atom(attr_name) do
    if MapSet.member?(ctx.ignored_attrs, attr_name) do
      skipped(node, acc)
    else
      do_walk_call(node, ctx, acc)
    end
  end

  # Regular call nodes — walk children, fingerprint if large enough
  defp walk({form, _meta, args} = node, ctx, acc) when is_list(args) do
    if excluded_macro?(form, ctx.excluded) do
      skipped(node, acc)
    else
      do_walk_call(node, ctx, acc)
    end
  end

  defp walk({left, right}, ctx, acc) do
    {acc, subs_l, mass_l, line_l} = walk(left, ctx, acc)
    {acc, subs_r, mass_r, line_r} = walk(right, ctx, acc)
    {acc, MapSet.union(subs_l, subs_r), 1 + mass_l + mass_r, min_line(line_l, line_r)}
  end

  defp walk(list, ctx, acc) when is_list(list) do
    {acc, subs, mass, line} = walk_children(list, ctx, acc)
    {acc, subs, mass, line}
  end

  defp walk({_name, meta, context}, _ctx, acc) when is_atom(context),
    do: {acc, MapSet.new(), 1, meta_line(meta)}

  defp walk(_leaf, _ctx, acc), do: {acc, MapSet.new(), 1, nil}

  defp skipped(node, acc) do
    {line, _} = Location.line_range(node)
    {acc, MapSet.new(), mass(node), line}
  end

  defp do_walk_call({form, meta, args} = node, ctx, acc) do
    {acc, child_subs, child_mass, child_line} = walk_children(args, ctx, acc)

    mass = 1 + child_mass
    line = min_line(meta_line(meta), child_line)

    my_sub_hash =
      if ctx.sub_hashes and mass >= @sub_hash_min_mass do
        child_forms = Enum.map(args, &child_form/1)
        MapSet.new([:erlang.phash2({form, child_forms, mass})])
      else
        MapSet.new()
      end

    all_subs = MapSet.union(child_subs, my_sub_hash)

    if mass >= ctx.min_mass do
      normalized = Normalizer.normalize(node, ctx.norm_opts)
      hash = compute_hash(normalized)

      frag = %{
        hash: hash,
        mass: mass,
        ast: node,
        file: ctx.file,
        line: line || 0,
        sub_hashes: all_subs
      }

      {[frag | acc], all_subs, mass, line}
    else
      {acc, all_subs, mass, line}
    end
  end

  defp walk_children(children, ctx, acc) do
    Enum.reduce(children, {acc, MapSet.new(), 0, nil}, fn child, {a, subs, m, l} ->
      {a, child_s, child_m, child_l} = walk(child, ctx, a)
      {a, MapSet.union(subs, child_s), m + child_m, min_line(l, child_l)}
    end)
  end

  defp meta_line(meta) when is_list(meta), do: Keyword.get(meta, :line)
  defp meta_line(_meta), do: nil

  defp min_line(nil, line), do: line
  defp min_line(line, nil), do: line
  defp min_line(a, b), do: min(a, b)

  # --- Sibling windows ---

  defp module_body?(children, ctx) do
    length(children) <= ctx.max_module_forms and
      Enum.any?(children, fn
        {form, _, _} when form in @module_level_forms -> true
        _ -> false
      end)
  end

  defp sibling_windows([], _per_child, _ctx, acc), do: acc
  defp sibling_windows([_], _per_child, _ctx, acc), do: acc

  defp sibling_windows(children, per_child, ctx, acc) do
    children_with_info =
      children
      |> Enum.zip(per_child)
      |> Enum.reject(fn
        {{:@, _, [{attr_name, _, _}]}, _} when is_atom(attr_name) ->
          MapSet.member?(ctx.ignored_attrs, attr_name)

        {{form, _, _}, _} ->
          excluded_macro?(form, ctx.excluded)

        _ ->
          false
      end)

    len = length(children_with_info)
    max_win = min(ctx.max_window_size, len)

    Enum.reduce(2..max_win//1, acc, fn window_size, acc_outer ->
      children_with_info
      |> Enum.chunk_every(window_size, 1, :discard)
      |> Enum.reduce(acc_outer, fn window_with_info, acc_inner ->
        maybe_window_fragment(window_with_info, ctx, acc_inner)
      end)
    end)
  end

  defp maybe_window_fragment(window_with_info, ctx, acc) do
    {window, infos} = Enum.unzip(window_with_info)
    combined_mass = Enum.reduce(infos, 0, fn {_s, m, _l}, sum -> sum + m end)

    if combined_mass < ctx.min_mass do
      acc
    else
      synthetic = {:__block__, [], window}
      normalized = Normalizer.normalize(synthetic, ctx.norm_opts)
      hash = compute_hash(normalized)

      frag = %{
        hash: hash,
        mass: combined_mass,
        ast: synthetic,
        file: ctx.file,
        line: Enum.reduce(infos, nil, fn {_s, _m, l}, acc -> min_line(acc, l) end) || 0,
        sub_hashes:
          Enum.reduce(infos, MapSet.new(), fn {s, _m, _l}, acc -> MapSet.union(s, acc) end)
      }

      [frag | acc]
    end
  end

  # --- Helpers ---

  defp child_form({form, _, _}) when is_atom(form), do: form
  defp child_form({form, _, _}) when is_tuple(form), do: :remote_call
  defp child_form(_), do: :leaf

  defp excluded_macro?(form, excluded) when is_atom(form), do: MapSet.member?(excluded, form)
  defp excluded_macro?(_, _), do: false

  @doc """
  Count the number of AST nodes in a tree (its "mass").
  """
  @spec mass(Macro.t()) :: non_neg_integer()
  def mass({_form, _meta, args}) when is_list(args) do
    1 + Enum.sum(Enum.map(args, &mass/1))
  end

  def mass({left, right}), do: 1 + mass(left) + mass(right)

  def mass(list) when is_list(list) do
    Enum.sum(Enum.map(list, &mass/1))
  end

  def mass(_leaf), do: 1

  @doc """
  Compute a deterministic hash for a normalized AST.
  """
  @spec compute_hash(Macro.t()) :: hash()
  def compute_hash(normalized_ast) do
    normalized_ast
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:blake2b, &1))
  end
end
