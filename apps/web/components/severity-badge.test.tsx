import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "./severity-badge";

describe("SeverityBadge", () => {
  it("renders severity text so meaning does not depend on color", () => {
    render(React.createElement(SeverityBadge, { severity: "CRITICAL" }));
    expect(screen.getByText("CRITICAL")).toBeVisible();
  });
});
