const BUTTON_BASE =
  "brutal-lift border-2 border-foreground font-mono font-bold uppercase tracking-widest shadow-brutal-sm";

export const BUTTON_PRIMARY = `${BUTTON_BASE} h-10 bg-acid px-4 text-xs text-foreground hover:bg-acid`;
export const BUTTON_SECONDARY = `${BUTTON_BASE} h-10 bg-card px-4 text-xs text-foreground hover:bg-card`;
export const BUTTON_DANGER = `${BUTTON_BASE} h-10 bg-crit px-4 text-xs text-foreground hover:bg-crit`;
export const BUTTON_SMALL = `${BUTTON_BASE} h-8 bg-card px-3 text-[11px] text-foreground hover:bg-card`;
export const BUTTON_SMALL_ACID = `${BUTTON_BASE} h-8 bg-acid px-3 text-[11px] text-foreground hover:bg-acid`;
export const ICON_BUTTON = `${BUTTON_BASE} size-8 bg-card p-0 text-foreground hover:bg-card aria-expanded:bg-acid`;

export const FIELD_CONTROL =
  "h-11 w-full border-2 border-foreground bg-card px-3 font-mono text-sm shadow-brutal-sm placeholder:text-muted-foreground/70 focus-visible:border-foreground focus-visible:bg-acid/15 focus-visible:ring-0";

export const SELECT_TRIGGER =
  "h-11 w-full rounded-none border-2 border-foreground bg-card px-3 font-mono text-sm shadow-brutal-sm hover:bg-card focus-visible:border-foreground focus-visible:bg-acid/15 focus-visible:ring-0 data-popup-open:bg-acid/15 dark:bg-card";
export const SELECT_CONTENT = "brutal rounded-none bg-card p-0 ring-0";
export const SELECT_ITEM =
  "rounded-none px-3 py-2.5 font-mono text-sm focus:bg-acid focus:text-foreground data-highlighted:bg-acid data-highlighted:text-foreground";

export const MENU_CONTENT = "brutal w-48 rounded-none bg-card p-0 ring-0";
export const MENU_ITEM =
  "m-1 gap-2 rounded-none px-3 py-2.5 font-mono text-[11px] font-bold uppercase tracking-widest focus:bg-acid focus:text-foreground";

export const SWITCH =
  "data-[size=default]:h-7 data-[size=default]:w-12 rounded-none border-2 border-foreground bg-card data-checked:bg-acid data-unchecked:bg-card focus-visible:ring-0 [&>span]:ml-0.5 [&>span]:size-4! [&>span]:rounded-none! [&>span]:bg-foreground! [&>span]:data-checked:translate-x-6! [&>span]:data-unchecked:translate-x-0!";

export const SHEET_CONTENT =
  "brutal w-full gap-0 rounded-none bg-card p-0 ring-0 data-[side=right]:sm:max-w-md";
export const DIALOG_CONTENT = "brutal gap-0 rounded-none bg-card p-0 ring-0 sm:max-w-lg";
export const PANEL_HEADER =
  "flex items-start justify-between gap-4 border-b-2 border-foreground bg-foreground px-6 py-4 text-background";
export const PANEL_TITLE = "font-mono text-sm font-bold uppercase tracking-widest text-background";
export const PANEL_CLOSE =
  "flex size-8 shrink-0 items-center justify-center border-2 border-background text-background outline-none transition-colors hover:bg-acid hover:text-foreground focus-visible:bg-acid focus-visible:text-foreground";
