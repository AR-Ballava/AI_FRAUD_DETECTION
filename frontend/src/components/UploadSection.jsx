import { FileText, Loader2, Upload, Wand2, X } from 'lucide-react';
import { useRef, useState } from 'react';

const sampleText =
  'Company: FutureTech Global\nPosition: Data Analyst\nRecruiter: Amit Sharma\nEmail: futuretech.hr@gmail.com\nUrgent offer letter. Pay a refundable processing fee within 24 hours to confirm direct joining. No interview required.';

function UploadSection({ onAnalyze, loading, error }) {
  const [text, setText] = useState('');
  const [file, setFile] = useState(null);
  const [dragging, setDragging] = useState(false);
  const [mode, setMode] = useState('text');
  const fileInputRef = useRef(null);

  function handleDrop(event) {
    event.preventDefault();
    setDragging(false);
    const nextFile = event.dataTransfer.files?.[0];
    if (nextFile) {
      setFile(nextFile);
    }
  }

  function submit() {
    onAnalyze({ text, file: mode === 'upload' ? file : null, sourceType: mode === 'upload' ? 'upload' : 'text' });
  }

  return (
    <div className="analysis-panel">
      <div className="detector-tabs" role="tablist" aria-label="Input mode">
        <button className={mode === 'text' ? 'active' : ''} type="button" onClick={() => setMode('text')}>
          <FileText size={16} />
          Paste Text
        </button>
        <button className={mode === 'upload' ? 'active' : ''} type="button" onClick={() => setMode('upload')}>
          <Upload size={16} />
          Upload PDF
        </button>
      </div>

      {mode === 'upload' && (
        <div
          className={`drop-zone ${dragging ? 'is-dragging' : ''}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
        >
          <Upload size={24} />
          <div>
            <strong>{file ? file.name : 'Drop PDF or text file'}</strong>
            <span>{file ? `${Math.round(file.size / 1024)} KB selected` : 'PDF, TXT, MD, or EML'}</span>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf,.txt,.md,.eml,application/pdf,text/plain"
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />
        </div>
      )}

      {mode === 'upload' && file && (
        <button className="text-button" type="button" onClick={() => setFile(null)}>
          <X size={16} />
          Clear file
        </button>
      )}

      {mode === 'text' && (
        <>
          <div className="panel-title-row compact-title">
            <label className="text-input-label" htmlFor="analysis-text">
              Raw Text
            </label>
            <button className="icon-button" type="button" onClick={() => setText(sampleText)} title="Load sample text">
              <Wand2 size={18} />
            </button>
          </div>
          <textarea
            id="analysis-text"
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Paste job offer, recruitment email, or suspicious terms here..."
          />
        </>
      )}

      {error && <p className="form-error">{error}</p>}

      <button className="primary-button" type="button" disabled={loading || (mode === 'upload' ? !file : !text.trim())} onClick={submit}>
        {loading ? <Loader2 className="spin" size={18} /> : <SearchIcon />}
        {loading ? 'Analyzing' : 'Analyze'}
      </button>
    </div>
  );
}

function SearchIcon() {
  return <Wand2 size={18} />;
}

export default UploadSection;
