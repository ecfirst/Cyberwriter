import ReactModal from "react-modal";
import { createRoot } from "react-dom/client";
import { useMemo, useState } from "react";
import * as Y from "yjs";

import PageGraphqlProvider from "../../graphql/client";
import { ConnectionStatus, usePageConnection } from "../connection";
import { usePlainField } from "../plain_editors/field";

function JsonField({
    label,
    description,
    mapKey,
    provider,
    connected,
    setEditing,
}: {
    label: string;
    description?: string;
    mapKey: string;
    provider: ReturnType<typeof usePageConnection>["provider"];
    connected: boolean;
    setEditing?: (editing: boolean) => void;
}) {
    const map = useMemo(
        () => provider.document.get("plain_fields", Y.Map<string>),
        [provider]
    );
    const [value, setValue] = usePlainField<string>(map, mapKey, "{}");
    const [draft, setDraft] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const displayValue = draft ?? value;

    const applyDraft = () => {
        if (draft === null) return;
        try {
            const parsed = JSON.parse(draft || "{}") as unknown;
            const normalized = JSON.stringify(parsed, null, 2);
            setValue(normalized);
            setDraft(null);
            setError(null);
            if (setEditing) setEditing(false);
        } catch (exc) {
            setError("Please provide valid JSON.");
        }
    };

    return (
        <div className="form-group col-12">
            <label>{label}</label>
            <textarea
                className="form-control"
                value={displayValue}
                disabled={!connected}
                rows={12}
                onChange={(ev) => {
                    setDraft(ev.target.value);
                    if (setEditing) setEditing(true);
                }}
                onBlur={() => applyDraft()}
            />
            {description && (
                <small className="form-text text-muted">{description}</small>
            )}
            {error && <div className="text-danger small mt-1">{error}</div>}
        </div>
    );
}

function WorkbookForm() {
    const { provider, status, connected, setEditing } = usePageConnection({
        model: "project_workbook",
    });

    return (
        <div className="row">
            <div className="col-12 mb-3">
                <ConnectionStatus status={status} />
            </div>
            <JsonField
                label="Workbook Data"
                description="Edit the parsed workbook JSON that drives reporting questions."
                mapKey="workbookData"
                provider={provider}
                connected={connected}
                setEditing={setEditing}
            />
            <JsonField
                label="Workbook Responses"
                description="Modify collected responses or add new ones keyed by workbook entries."
                mapKey="dataResponses"
                provider={provider}
                connected={connected}
                setEditing={setEditing}
            />
        </div>
    );
}

document.addEventListener("DOMContentLoaded", () => {
    ReactModal.setAppElement(
        document.querySelector("div.wrapper") as HTMLElement
    );
    const root = createRoot(document.getElementById("collab-form-container")!);
    root.render(
        <PageGraphqlProvider>
            <WorkbookForm />
        </PageGraphqlProvider>
    );
});
