import { useRouteError } from "react-router";
import { TriangleAlert } from "lucide-react";
import { Button, Card, EmptyState } from "../components/ui";

/** Shown in place of a page that failed to render, instead of a blank screen. */
export function PageError() {
  const error = useRouteError();
  const message = error instanceof Error ? error.message : String(error);
  return (
    <Card>
      <EmptyState
        icon={<TriangleAlert className="size-6" />}
        title="This page could not be displayed"
        description={`Something unexpected happened while showing this page: ${message}`}
        action={<Button onClick={() => window.location.reload()}>Reload page</Button>}
      />
    </Card>
  );
}
