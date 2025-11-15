import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";

const cx = (...c: Array<string | false | undefined>) => c.filter(Boolean).join(" ");

export function Button({ variant = "primary", className, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "danger" }) {
  return (
    <button
      {...props}
      className={cx(
        "inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium transition disabled:opacity-50",
        variant === "primary" && "bg-zinc-900 text-white hover:bg-zinc-700",
        variant === "ghost" && "text-zinc-700 hover:bg-zinc-100",
        variant === "danger" && "bg-red-600 text-white hover:bg-red-500",
        className,
      )}
    />
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cx("w-full rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm outline-none focus:border-zinc-900", props.className)}
    />
  );
}

export function Card({ title, children, actions }: { title?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm">
      {(title || actions) && (
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-700">{title}</h2>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

const tones = {
  green: "bg-emerald-100 text-emerald-800",
  amber: "bg-amber-100 text-amber-800",
  red: "bg-red-100 text-red-800",
  zinc: "bg-zinc-100 text-zinc-700",
  blue: "bg-sky-100 text-sky-800",
};

export function Badge({ tone = "zinc", children }: { tone?: keyof typeof tones; children: ReactNode }) {
  return <span className={cx("inline-flex rounded px-1.5 py-0.5 text-xs font-medium", tones[tone])}>{children}</span>;
}

export function Copy({ value }: { value: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 overflow-x-auto rounded bg-zinc-100 px-2 py-1 text-xs whitespace-nowrap">{value}</code>
      <Button variant="ghost" onClick={() => void navigator.clipboard.writeText(value)}>
        Copy
      </Button>
    </div>
  );
}

export function ErrorText({ error }: { error: Error | null }) {
  return error ? <p className="text-sm text-red-600">{error.message}</p> : null;
}
