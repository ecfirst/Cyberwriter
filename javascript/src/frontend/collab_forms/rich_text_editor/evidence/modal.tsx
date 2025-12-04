import { useContext, useEffect, useId, useRef, useState } from "react";
import ReactModal from "react-modal";
import { EvidencesContext } from "../../../../tiptap_gw/evidence";
import { Editor } from "@tiptap/react";
import EvidenceUploadForm from "./upload";

export default function EvidenceModal(props: {
    editor: Editor;
    initialId: null | number;
    setEvidenceId: (id: number | null) => void | Promise<void>;
}) {
    const [uploadMode, setUploadMode] = useState<boolean>(false);

    let content;
    if (uploadMode) {
        content = (
            <EvidenceUploadForm
                switchMode={() => setUploadMode(false)}
                onSubmit={props.setEvidenceId}
            />
        );
    } else {
        content = (
            <EvidenceSelectForm
                initial={props.initialId}
                switchMode={() => setUploadMode(true)}
                onSubmit={props.setEvidenceId}
            />
        );
    }

    return (
        <ReactModal
            isOpen
            onRequestClose={() => props.setEvidenceId(null)}
            contentLabel="Insert Evidence"
            className="modal-dialog modal-dialog-centered"
        >
            <div className="modal-content">
                <div className="modal-header">
                    <h5 className="modal-title">
                        {props.initialId === null ? "Insert" : "Edit"} Evidence
                    </h5>
                </div>
                {content}
            </div>
        </ReactModal>
    );
}

function EvidenceSelectForm(props: {
    initial: number | null;
    onSubmit: (id: number | null) => void | Promise<void>;
    switchMode: () => void;
}) {
    const evidences = useContext(EvidencesContext);
    const [selectedId, setSelectedId] = useState<number | null>(null);
    const [saving, setSaving] = useState(false);
    const isMounted = useRef(true);
    const nameId = useId();

    useEffect(() => {
        return () => {
            isMounted.current = false;
        };
    }, []);
    return (
        <>
            <div className="modal-body">
                <div className="form-group">
                    <label htmlFor={nameId}>Evidence Name</label>
                    <select
                        className="custom-select custom-select-lg"
                        value={selectedId?.toString()}
                        onChange={(e) =>
                            setSelectedId(
                                e.target.value === ""
                                    ? null
                                    : parseInt(e.target.value)
                            )
                        }
                    >
                        <option value="">Select Evidence...</option>
                        {evidences?.evidence?.map((e) => (
                            <option value={e.id} key={e.id}>
                                {e.friendlyName}
                            </option>
                        ))}
                    </select>
                </div>
            </div>

            <div className="modal-footer">
                <button
                    className="btn btn-secondary"
                    disabled={saving}
                    onClick={(e) => {
                        e.preventDefault();
                        props.switchMode();
                    }}
                >
                    Upload New
                </button>
                <button
                    className="btn btn-primary"
                    disabled={selectedId === null || saving}
                    onClick={async (e) => {
                        e.preventDefault();
                        setSaving(true);
                        try {
                            await props.onSubmit(selectedId);
                        } finally {
                            if (isMounted.current) setSaving(false);
                        }
                    }}
                >
                    {saving && (
                        <span
                            className="spinner-border spinner-border-sm mr-2"
                            role="status"
                            aria-hidden="true"
                        />
                    )}
                    {saving
                        ? "Saving..."
                        : props.initial === null
                          ? "Insert"
                          : "Save"}
                </button>
                <button
                    className="btn btn-secondary-outline"
                    disabled={saving}
                    onClick={(e) => {
                        e.preventDefault();
                        props.onSubmit(null);
                    }}
                >
                    Cancel
                </button>
            </div>
        </>
    );
}
