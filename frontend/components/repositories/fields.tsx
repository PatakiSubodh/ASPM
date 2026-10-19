import type { ComponentProps, ReactNode } from "react";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { FIELD_LABEL } from "@/lib/auth-styles";
import type { Option } from "@/lib/repositories";

import {
  FIELD_CONTROL,
  SELECT_CONTENT,
  SELECT_ITEM,
  SELECT_TRIGGER,
  SWITCH,
} from "./styles";

export function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className={FIELD_LABEL}>
        {label}
      </Label>
      {children}
      {hint && <p className="font-mono text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function TextField({
  id,
  name,
  label,
  hint,
  ...props
}: {
  id: string;
  name: string;
  label: string;
  hint?: string;
} & Omit<ComponentProps<"input">, "id" | "name">) {
  return (
    <Field id={id} label={label} hint={hint}>
      <Input id={id} name={name} className={FIELD_CONTROL} {...props} />
    </Field>
  );
}

export function SelectField({
  id,
  name,
  label,
  hint,
  options,
  defaultValue,
}: {
  id: string;
  name: string;
  label: string;
  hint?: string;
  options: Option[];
  defaultValue?: string;
}) {
  return (
    <Field id={id} label={label} hint={hint}>
      <Select name={name} items={options} defaultValue={defaultValue ?? options[0]?.value} required>
        <SelectTrigger id={id} className={SELECT_TRIGGER}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent alignItemWithTrigger={false} className={SELECT_CONTENT}>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value} className={SELECT_ITEM}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  );
}

export function ToggleField({
  id,
  name,
  label,
  hint,
  defaultChecked,
}: {
  id: string;
  name: string;
  label: string;
  hint: string;
  defaultChecked?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-6 border-2 border-dashed border-foreground/40 p-4">
      <div className="space-y-1">
        <Label htmlFor={id} className={FIELD_LABEL}>
          {label}
        </Label>
        <p className="font-mono text-[11px] text-muted-foreground">{hint}</p>
      </div>
      <Switch id={id} name={name} defaultChecked={defaultChecked} className={SWITCH} />
    </div>
  );
}
