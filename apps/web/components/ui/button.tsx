import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva("inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 disabled:pointer-events-none disabled:opacity-50", {
  variants: {
    variant: { default: "bg-primary px-4 py-2 text-slate-950 hover:brightness-110", outline: "border border-white/10 bg-white/[.03] px-4 py-2 hover:bg-white/[.07]", ghost: "px-3 py-2 hover:bg-white/[.06]", danger: "bg-red-500 px-4 py-2 text-white hover:bg-red-400" },
    size: { default: "h-10", sm: "h-8 text-xs", lg: "h-12 px-6" }
  }, defaultVariants: { variant: "default", size: "default" }
});

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> { asChild?: boolean }
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, asChild, ...props }, ref) => {
  const Component = asChild ? Slot : "button";
  return <Component className={cn(buttonVariants({ variant, size }), className)} ref={ref} {...props} />;
});
Button.displayName = "Button";
