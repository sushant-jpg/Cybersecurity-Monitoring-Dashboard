import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureWatch | Security Operations",
  description: "Cybersecurity monitoring and threat detection platform"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" className="dark"><body>{children}</body></html>;
}
