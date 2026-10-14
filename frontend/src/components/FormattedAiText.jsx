import React, { useState } from 'react';

/**
 * Component hiển thị văn bản Markdown được AI sinh ra với giao diện phong cách Cyber / An Ninh Mạng cao cấp.
 * Hỗ trợ: Headers, danh sách, khối mã lệnh (Code Block có nút Copy), Bảng (Table), Trích dẫn & Callout (Cảnh báo bảo mật).
 */
export default function FormattedAiText({ text, content, className = '' }) {
  const rawText = text || content || '';
  if (!rawText) return null;

  const lines = rawText.split('\n');
  const elements = [];
  let inCodeBlock = false;
  let codeLanguage = '';
  let codeBuffer = [];
  let tableBuffer = [];
  let inTable = false;

  const flushTable = (keyIndex) => {
    if (tableBuffer.length === 0) return null;
    const rows = [...tableBuffer];
    tableBuffer = [];
    inTable = false;

    // Phân tích header và body của bảng
    const headerLine = rows[0];
    const headers = headerLine
      .split('|')
      .map((c) => c.trim())
      .filter((c, i, arr) => i !== 0 && i !== arr.length - 1 || c.length > 0);

    const dataRows = rows.slice(rows.length > 1 && rows[1].includes('---') ? 2 : 1);

    return (
      <div key={`table-${keyIndex}`} className="ai-table-container">
        <table className="ai-markdown-table">
          {headers.length > 0 && (
            <thead>
              <tr>
                {headers.map((h, hi) => (
                  <th key={hi}>{formatInline(h)}</th>
                ))}
              </tr>
            </thead>
          )}
          <tbody>
            {dataRows.map((rowStr, ri) => {
              const cells = rowStr
                .split('|')
                .map((c) => c.trim())
                .filter((c, i, arr) => i !== 0 && i !== arr.length - 1 || c.length > 0);
              return (
                <tr key={ri}>
                  {cells.map((cell, ci) => (
                    <td key={ci}>{formatInline(cell)}</td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  lines.forEach((line, index) => {
    // 1. Kiểm tra Code block
    if (line.trim().startsWith('```')) {
      if (inTable) {
        elements.push(flushTable(index));
      }

      if (inCodeBlock) {
        elements.push(
          <AiCodeBlock
            key={`code-${index}`}
            code={codeBuffer.join('\n')}
            language={codeLanguage}
          />
        );
        codeBuffer = [];
        codeLanguage = '';
        inCodeBlock = false;
      } else {
        inCodeBlock = true;
        codeLanguage = line.trim().replace(/^```/, '').trim() || 'cmd';
      }
      return;
    }

    if (inCodeBlock) {
      codeBuffer.push(line);
      return;
    }

    // 2. Kiểm tra Table markdown (| col1 | col2 |)
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      inTable = true;
      tableBuffer.push(line.trim());
      return;
    } else if (inTable) {
      elements.push(flushTable(index));
    }

    // 3. Format Callout cảnh báo an ninh (Ví dụ: > [!WARNING], > [!DANGER], > [!NOTE], > [!TIP] hoặc > trích dẫn)
    if (line.trim().startsWith('>')) {
      const quoteContent = line.trim().replace(/^>\s?/, '');
      let calloutType = 'note';
      let cleanContent = quoteContent;

      if (quoteContent.startsWith('[!WARNING]') || quoteContent.toLowerCase().includes('cảnh báo') || quoteContent.toLowerCase().includes('nguy hiểm')) {
        calloutType = 'warning';
        cleanContent = quoteContent.replace(/\[!WARNING\]/i, '').trim();
      } else if (quoteContent.startsWith('[!DANGER]') || quoteContent.toLowerCase().includes('critical') || quoteContent.toLowerCase().includes('lỗ hổng')) {
        calloutType = 'danger';
        cleanContent = quoteContent.replace(/\[!DANGER\]/i, '').trim();
      } else if (quoteContent.startsWith('[!TIP]') || quoteContent.toLowerCase().includes('khuyến nghị') || quoteContent.toLowerCase().includes('lời khuyên')) {
        calloutType = 'tip';
        cleanContent = quoteContent.replace(/\[!TIP\]/i, '').trim();
      }

      elements.push(
        <div key={index} className={`ai-callout ai-callout-${calloutType}`}>
          <div className="ai-callout-icon">
            {calloutType === 'warning' && <i className="fa-solid fa-triangle-exclamation"></i>}
            {calloutType === 'danger' && <i className="fa-solid fa-shield-virus"></i>}
            {calloutType === 'tip' && <i className="fa-solid fa-lightbulb"></i>}
            {calloutType === 'note' && <i className="fa-solid fa-circle-info"></i>}
          </div>
          <div className="ai-callout-text">{formatInline(cleanContent)}</div>
        </div>
      );
      return;
    }

    // 4. Format Headers
    if (line.startsWith('### ')) {
      elements.push(
        <h4 key={index} className="ai-heading-3">
          <span>{formatInline(line.replace('### ', ''))}</span>
        </h4>
      );
    } else if (line.startsWith('## ')) {
      elements.push(
        <h3 key={index} className="ai-heading-2">
          <span>{formatInline(line.replace('## ', ''))}</span>
        </h3>
      );
    } else if (line.startsWith('# ')) {
      elements.push(
        <h2 key={index} className="ai-heading-1">
          <span>{formatInline(line.replace('# ', ''))}</span>
        </h2>
      );
    } 
    // 5. Format Lists
    else if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      elements.push(
        <div key={index} className="ai-list-item">
          <span className="ai-bullet">✦</span>
          <span className="ai-list-content">{formatInline(line.trim().substring(2))}</span>
        </div>
      );
    } else if (/^\d+\.\s/.test(line.trim())) {
      const match = line.trim().match(/^(\d+\.)\s(.*)/);
      elements.push(
        <div key={index} className="ai-list-item numbered">
          <span className="ai-number-badge">{match[1]}</span>
          <span className="ai-list-content">{formatInline(match[2])}</span>
        </div>
      );
    } 
    // 6. Dòng phân cách hoặc dòng trống
    else if (line.trim() === '---' || line.trim() === '===') {
      elements.push(<hr key={index} className="ai-divider" />);
    } else if (line.trim() === '') {
      elements.push(<div key={index} className="ai-empty-line" />);
    } 
    // 7. Đoạn văn bản thông thường
    else {
      elements.push(
        <p key={index} className="ai-paragraph">
          {formatInline(line)}
        </p>
      );
    }
  });

  if (inTable && tableBuffer.length > 0) {
    elements.push(flushTable(lines.length));
  }

  if (inCodeBlock && codeBuffer.length > 0) {
    elements.push(
      <AiCodeBlock
        key="code-end"
        code={codeBuffer.join('\n')}
        language={codeLanguage}
      />
    );
  }

  return <div className={`formatted-ai-text ${className}`}>{elements}</div>;
}

/**
 * Component Khối Code có nút sao chép (Copy) tiện lợi và thanh header đẹp mắt
 */
function AiCodeBlock({ code, language }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="ai-code-wrapper">
      <div className="ai-code-header">
        <div className="ai-code-lang">
          <i className="fa-solid fa-terminal"></i>
          <span>{language || 'cmd'}</span>
        </div>
        <button
          type="button"
          className={`ai-copy-btn ${copied ? 'copied' : ''}`}
          onClick={handleCopy}
          title="Sao chép mã lệnh"
        >
          {copied ? (
            <>
              <i className="fa-solid fa-check"></i>
              <span>Đã sao chép!</span>
            </>
          ) : (
            <>
              <i className="fa-regular fa-copy"></i>
              <span>Sao chép</span>
            </>
          )}
        </button>
      </div>
      <pre className="ai-code-block">
        <code>{code}</code>
      </pre>
    </div>
  );
}

/**
 * Phân tích cú pháp chuỗi nội dòng (Inline markdown): `code`, **bold**, *italic*, [link](url)
 */
function formatInline(str) {
  if (!str) return '';

  const parts = [];
  const regex = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[([^\]]+)\]\(([^)]+)\))/g;
  let lastIdx = 0;
  let match;
  let key = 0;

  while ((match = regex.exec(str)) !== null) {
    if (match.index > lastIdx) {
      parts.push(str.substring(lastIdx, match.index));
    }
    const token = match[0];

    if (token.startsWith('`') && token.endsWith('`')) {
      parts.push(
        <code key={key++} className="ai-inline-code">
          {token.slice(1, -1)}
        </code>
      );
    } else if (token.startsWith('**') && token.endsWith('**')) {
      parts.push(
        <strong key={key++} className="ai-strong">
          {token.slice(2, -2)}
        </strong>
      );
    } else if (token.startsWith('*') && token.endsWith('*')) {
      parts.push(<em key={key++} className="ai-italic">{token.slice(1, -1)}</em>);
    } else if (token.startsWith('[')) {
      const label = match[2];
      const url = match[3];
      parts.push(
        <a
          key={key++}
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="ai-link"
        >
          {label} <i className="fa-solid fa-arrow-up-right-from-square ai-link-icon"></i>
        </a>
      );
    }
    lastIdx = regex.lastIndex;
  }

  if (lastIdx < str.length) {
    parts.push(str.substring(lastIdx));
  }

  return parts.length > 0 ? parts : str;
}
