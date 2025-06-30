import sys
import pdfplumber


def extract_pages(pdf_path):
    pages = []
    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ''
            pages.append({'page': i, 'text': text})
    return pages


def find_answer(pages, question):
    keywords = [w.lower() for w in question.strip('?').split() if w]
    for p in pages:
        text_lower = p['text'].lower()
        if all(k in text_lower for k in keywords):
            return p
    return None


def best_match(pages, question):
    """Return the page with the most keyword matches."""
    keywords = [w.lower() for w in question.strip('?').split() if w]
    best = None
    best_score = 0
    for p in pages:
        text_lower = p['text'].lower()
        score = sum(text_lower.count(k) for k in keywords)
        if score > best_score:
            best = p
            best_score = score
    if not best or best_score == 0:
        return None
    snippet = best['text'][:300]
    return {'page': best['page'], 'text': snippet}


def main():
    if len(sys.argv) < 3:
        print('Usage: python search_pdf.py <pdf_path> "<question>"')
        return
    pdf_path = sys.argv[1]
    question = sys.argv[2]
    pages = extract_pages(pdf_path)
    result = best_match(pages, question)
    if result:
        print(f"Page {result['page']}:\n{result['text']}")
    else:
        print('Answer not found')


if __name__ == '__main__':
    main()
