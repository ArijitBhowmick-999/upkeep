import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Upkeep — Static Analysis & Code Refactoring",
  description:
    "Developer platform for maintainability scoring, technical debt inspection, and automated code refactoring.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 text-slate-900 antialiased">
        {children}
      </body>
    </html>
  );
}
