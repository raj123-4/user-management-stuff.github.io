import sys
import pdfplumber
from PIL import Image
import tempfile


def extract_pages(pdf_path):
    pages = []
    with pdfplumber.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ''
            pages.append({'page': i, 'text': text})
    return pages


def best_match(pages, question):
    keywords = [w.lower() for w in question.strip('?').split() if w]
    best = None
    best_score = 0
    for p in pages:
        text_lower = p['text'].lower()
        score = sum(text_lower.count(k) for k in keywords)
        if score > best_score:
            best = p
            best_score = score
    if best and best_score > 0:
        snippet = best['text'][:300]
        return {'page': best['page'], 'text': snippet}
    return None


def show_page_image(pdf_path, page_num):
    try:
        with pdfplumber.open(pdf_path) as pdf:
            page = pdf.pages[page_num - 1]
            img = page.to_image(resolution=150)
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                img.save(tmp.name, format='PNG')
                Image.open(tmp.name).show()
    except Exception as e:
        print('Could not display page image:', e)


def main():
    if len(sys.argv) < 2:
        pdf_path = input('Enter path to PDF file: ')
    else:
        pdf_path = sys.argv[1]
    question = input('Enter your question: ')
    pages = extract_pages(pdf_path)
    result = best_match(pages, question)
    if result:
        print(f"Answer likely on page {result['page']}:")
        print(result['text'])
        show_page_image(pdf_path, result['page'])
    else:
        print('Answer not found')


if __name__ == '__main__':
    main()
