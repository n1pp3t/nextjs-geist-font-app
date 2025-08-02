import { Inter } from 'next/font/google';
import { NotificationCenter } from '@/components/NotificationCenter';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'FSociety Toolkit - Cybersecurity Education Platform',
  description: 'Educational platform for learning about cybersecurity tools and techniques',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <NotificationCenter />
        <div className="min-h-screen bg-background text-foreground">
          {children}
        </div>
      </body>
    </html>
  );
}
