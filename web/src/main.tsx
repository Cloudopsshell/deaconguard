import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Hosts } from "./pages/Hosts";
import { HostDetail } from "./pages/HostDetail";
import { ScanReport } from "./pages/ScanReport";
import { Vulnerabilities } from "./pages/Vulnerabilities";
import { VulnerabilityDetail } from "./pages/VulnerabilityDetail";
import { NotFound } from "./pages/NotFound";
import { PageError } from "./pages/PageError";
import { Login } from "./pages/Login";
import { Agents } from "./pages/Agents";
import { Audit } from "./pages/Audit";
import { Logs } from "./pages/Logs";
import { Schedules } from "./pages/Schedules";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: true } },
});

const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  {
    element: <Layout />,
    // A pathless child keeps the sidebar and scan console on screen when a page fails.
    children: [
      {
        errorElement: <PageError />,
        children: [
          { path: "/", element: <Dashboard /> },
          { path: "/hosts", element: <Hosts /> },
          { path: "/hosts/:hostId", element: <HostDetail /> },
          { path: "/scans/:scanId", element: <ScanReport /> },
          { path: "/vulnerabilities", element: <Vulnerabilities /> },
          { path: "/vulnerabilities/:cve", element: <VulnerabilityDetail /> },
          { path: "/agents", element: <Agents /> },
          { path: "/schedules", element: <Schedules /> },
          { path: "/logs", element: <Logs /> },
          { path: "/audit", element: <Audit /> },
          { path: "*", element: <NotFound /> },
        ],
      },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
