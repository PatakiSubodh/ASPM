"use client";

import { useEffect, useRef, useState, type ComponentProps } from "react";

import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const REACH = 3;

export function PasswordInput({ className, ...props }: Omit<ComponentProps<typeof Input>, "type">) {
  const [visible, setVisible] = useState(false);
  const [look, setLook] = useState({ x: 0, y: 0 });
  const eyes = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!visible) return;
    function track(event: PointerEvent) {
      const box = eyes.current?.getBoundingClientRect();
      if (!box) return;
      const angle = Math.atan2(
        event.clientY - (box.top + box.height / 2),
        event.clientX - (box.left + box.width / 2),
      );
      setLook({ x: Math.cos(angle) * REACH, y: Math.sin(angle) * REACH });
    }
    window.addEventListener("pointermove", track);
    return () => window.removeEventListener("pointermove", track);
  }, [visible]);

  return (
    <div className="relative">
      <Input
        {...props}
        type={visible ? "text" : "password"}
        onInput={() => setLook({ x: -REACH, y: 1 })}
        className={cn(className, "pr-16")}
      />
      <button
        ref={eyes}
        type="button"
        role="switch"
        aria-checked={visible}
        aria-label="Show password"
        title={visible ? "Hide password" : "Show password"}
        onClick={() => setVisible((v) => !v)}
        className="absolute top-1/2 right-3 flex -translate-y-1/2 cursor-pointer gap-1 p-1 outline-none focus-visible:bg-acid"
      >
        {[0, 1].map((eye) => (
          <span key={eye} aria-hidden className="relative size-5">
            <span
              className={cn(
                "absolute inset-0 flex items-center justify-center rounded-full border-2 border-foreground bg-card transition-transform duration-150 ease-out",
                !visible && "scale-y-0",
              )}
            >
              <span
                className="size-2 rounded-full bg-foreground transition-[translate] duration-100"
                style={{ translate: `${look.x}px ${look.y}px` }}
              />
            </span>
            <svg
              viewBox="0 0 20 20"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              strokeLinecap="round"
              className={cn(
                "absolute inset-0 size-5 text-foreground transition-opacity duration-150",
                visible && "opacity-0",
              )}
            >
              <path d="M3 9 Q10 16 17 9" />
              <path d="M6.5 11.6 L5 14.5 M10 12.5 L10 15.5 M13.5 11.6 L15 14.5" />
            </svg>
          </span>
        ))}
      </button>
    </div>
  );
}
