import { css } from 'lit';

/** Grid + cell chrome for {@link DataTable} (pages stamp cells into its shadow tree). */
export const dataTableStyles = css`
  :host {
    display: block;
    color: var(--fg, inherit);
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
    margin-bottom: 0.75rem;
  }
  .toolbar .grow {
    flex: 1 1 12rem;
    min-width: 10rem;
  }
  input[type='search'] {
    font: inherit;
    width: 100%;
    box-sizing: border-box;
    padding: 0.4rem 0.65rem;
    border: 1px solid var(--border, #d0d7de);
    border-radius: 6px;
    background: var(--card, #fff);
    color: var(--fg, inherit);
  }
  input[type='search']:focus-visible,
  button:focus-visible {
    outline: 2px solid var(--accent, #1f6feb);
    outline-offset: 1px;
  }
  .scroll {
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  table.fixed {
    min-width: 60rem;
    table-layout: fixed;
    font-size: 0.875rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.55rem 0.65rem;
    border-bottom: 1px solid var(--border, #d0d7de);
    vertical-align: top;
  }
  table.fixed th,
  table.fixed td {
    padding: 0.45rem 0.6rem;
    overflow-wrap: anywhere;
  }
  th {
    color: var(--muted, #656d76);
    font-weight: 600;
    white-space: nowrap;
  }
  th.right,
  td.right {
    text-align: right;
  }
  td.when {
    white-space: nowrap;
  }
  button.sort {
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
  }
  button.sort span {
    opacity: 0.45;
  }
  button.sort.active {
    color: var(--accent, #1f6feb);
  }
  button.sort.active span {
    opacity: 1;
  }
  button.toggle {
    width: 1.6rem;
    height: 1.6rem;
    padding: 0;
    border: none;
    border-radius: 4px;
    background: none;
    color: var(--muted, #656d76);
    font-size: 0.8rem;
    line-height: 1;
    cursor: pointer;
  }
  button.toggle:hover {
    background: color-mix(in srgb, var(--fg, #1f2328) 8%, transparent);
  }
  tr.open > td {
    border-bottom-color: transparent;
    background: color-mix(in srgb, var(--accent, #1f6feb) 5%, transparent);
  }
  tr.detail > td {
    padding: 0 0.6rem 0.9rem 3.1rem;
    background: color-mix(in srgb, var(--accent, #1f6feb) 5%, transparent);
  }
  a {
    color: var(--accent, #1f6feb);
    text-decoration: none;
    font-weight: 600;
  }
  a:hover {
    text-decoration: underline;
  }
  .muted {
    color: var(--muted, #656d76);
  }
  .error {
    color: var(--error, #cf222e);
  }
  .badge {
    display: inline-block;
    font-size: 0.75rem;
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
    border: 1px solid var(--border, #d0d7de);
    color: var(--muted, #656d76);
    white-space: nowrap;
  }
  .badge.write {
    border-color: color-mix(in srgb, var(--accent, #1f6feb) 60%, transparent);
    color: var(--accent, #1f6feb);
  }
  .badge.destructive,
  .badge.failed {
    border-color: color-mix(in srgb, var(--error, #cf222e) 60%, transparent);
    color: var(--error, #cf222e);
  }
  .used-by {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 0.75rem;
  }
  .line {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .line.tool {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .line.tool .badge {
    flex: none;
  }
  .line.tool button {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  button.link {
    padding: 0;
    border: none;
    background: none;
    color: var(--accent, #1f6feb);
    font: inherit;
    font-weight: 400;
    text-align: left;
    cursor: pointer;
  }
  button.link:hover {
    text-decoration: underline;
  }
  code {
    font-size: 0.85em;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 0;
  }
  dt {
    color: var(--muted, #656d76);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  pre {
    margin: 0.35rem 0 0;
    padding: 0.5rem;
    background: color-mix(in srgb, var(--fg, #1f2328) 5%, transparent);
    border-radius: 6px;
    font-size: 0.8rem;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .empty {
    margin: 0;
    color: var(--muted, #656d76);
  }
`;
