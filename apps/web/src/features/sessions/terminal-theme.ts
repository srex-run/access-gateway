import type { ITerminalOptions } from '@xterm/xterm'

export function terminalAppearance(): ITerminalOptions {
  return {
    fontSize: 14,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    // Remote ANSI/256-color/true-color output can request dark foregrounds.
    // Adjust their contrast against the actual cell background when rendering.
    minimumContrastRatio: 7,
    theme: {
      background: '#12151c',
      foreground: '#ffffff',
      cursor: '#ffffff',
      cursorAccent: '#12151c',
      selectionBackground: '#365880',
      selectionInactiveBackground: '#293345',
      selectionForeground: '#ffffff',
      black: '#202632',
      red: '#f7768e',
      green: '#9ece6a',
      yellow: '#e0af68',
      blue: '#7aa2f7',
      magenta: '#bb9af7',
      cyan: '#7dcfff',
      white: '#e2e8f0',
      brightBlack: '#94a3b8',
      brightRed: '#ff9caa',
      brightGreen: '#b9e38c',
      brightYellow: '#f5d28d',
      brightBlue: '#a6c5ff',
      brightMagenta: '#d6b5ff',
      brightCyan: '#a4e6ff',
      brightWhite: '#ffffff',
    },
  }
}
