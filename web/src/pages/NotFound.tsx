import { Link } from "react-router";
import { Compass } from "lucide-react";
import { Card, EmptyState } from "../components/ui";

export function NotFound() {
  return (
    <Card>
      <EmptyState
        icon={<Compass className="size-6" />}
        title="Page not found"
        description="The page you are looking for does not exist."
        action={
          <Link to="/" className="text-sm font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
            Back to dashboard
          </Link>
        }
      />
    </Card>
  );
}
