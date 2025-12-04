import { faLink } from "@fortawesome/free-solid-svg-icons/faLink";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Editor } from "@tiptap/core";
import { useId, useState } from "react";
import ReactModal from "react-modal";

export default function LinkButton(props: { editor: Editor }) {
    const { editor } = props;
    const [modalMode, setModalMode] = useState<null | "new" | "edit">(null);
    const [processing, setProcessing] = useState<null | "save" | "remove">(null);
    const [formUrl, setFormUrl] = useState("");
    const urlId = useId();

    const enabled = editor
        .can()
        .chain()
        .focus()
        .setLink({ href: "https://example.com" })
        .run();
    const active = editor.isActive("link");

    return (
        <>
            <button
                tabIndex={-1}
                title="Link"
                type="button"
                disabled={!enabled}
                className={active ? "is-active" : undefined}
                onClick={(e) => {
                    e.preventDefault();
                    const active = editor.isActive("link");
                    if (active) {
                        editor.chain().focus().extendMarkRange("link").run();
                        setFormUrl(editor.getAttributes("link").href);
                    } else {
                        setFormUrl("");
                    }
                    setProcessing(null);
                    setModalMode(active ? "edit" : "new");
                }}
            >
                <FontAwesomeIcon icon={faLink} />
            </button>
            <ReactModal
                isOpen={!!modalMode}
                onRequestClose={() => {
                    setProcessing(null);
                    setModalMode(null);
                }}
                contentLabel="Edit Link"
                className="modal-dialog modal-dialog-centered"
            >
                <div className="modal-content">
                    <div className="modal-header">
                        <h5 className="modal-title">Edit Link</h5>
                    </div>
                    <form
                        className="modal-body text-center"
                        onSubmit={(ev) => {
                            ev.preventDefault();
                            setProcessing("save");
                            if (formUrl) {
                                editor.chain().setLink({ href: formUrl }).run();
                            }
                            setModalMode(null);
                            setProcessing(null);
                        }}
                    >
                        <div className="form-group">
                            <label htmlFor={urlId}>URL</label>
                            <input
                                id={urlId}
                                type="url"
                                className="form-control"
                                value={formUrl}
                                autoFocus
                                onChange={(e) => setFormUrl(e.target.value)}
                            />
                        </div>

                        <div className="modal-footer">
                            <button
                                className="btn btn-primary"
                                disabled={processing !== null}
                            >
                                {processing === "save" && (
                                    <span
                                        className="spinner-border spinner-border-sm mr-2"
                                        role="status"
                                        aria-hidden="true"
                                    />
                                )}
                                {processing === "save" ? "Saving..." : "Save"}
                            </button>
                            {modalMode === "edit" && (
                                <button
                                    type="button"
                                    className="btn btn-danger"
                                    disabled={processing !== null}
                                    onClick={(e) => {
                                        e.preventDefault();
                                        setProcessing("remove");
                                        editor.chain().unsetLink().run();
                                        setModalMode(null);
                                        setProcessing(null);
                                    }}
                                >
                                    {processing === "remove" && (
                                        <span
                                            className="spinner-border spinner-border-sm mr-2"
                                            role="status"
                                            aria-hidden="true"
                                        />
                                    )}
                                    {processing === "remove"
                                        ? "Removing..."
                                        : "Remove"}
                                </button>
                            )}
                            <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={processing !== null}
                                onClick={(e) => {
                                    e.preventDefault();
                                    setModalMode(null);
                                }}
                            >
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            </ReactModal>
        </>
    );
}
