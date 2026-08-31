/** Modal dialog for creating a new project. */
import { Plus } from "lucide-react";
import type { FormEvent } from "react";

type CreateProjectModalProps = {
  onClose: () => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
};

export function CreateProjectModal({ onClose, onSubmit }: CreateProjectModalProps) {
  return (
    <div className="modal-backdrop">
      <form className="modal" onSubmit={onSubmit}>
        <div className="section-title">
          <h2>Create project</h2>
          <button type="button" className="secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <label>
          Project name
          <input name="name" minLength={2} required autoFocus />
        </label>
        <label>
          Client / organization
          <input name="client" />
        </label>
        <label>
          Description
          <textarea name="description" rows={3} />
        </label>
        <button type="submit">
          <Plus size={15} /> Create authorized project
        </button>
      </form>
    </div>
  );
}
