import React from "react";
import Groups from "./Groups";

export default function Group({ groupId }: { groupId?: string }): JSX.Element {
  return <Groups groupId={groupId} />;
}
