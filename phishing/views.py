from django.shortcuts import render
from django.http import JsonResponse
from .detector import detector

def index(request):
    """Renders the main interface for the Phishing Detector."""
    return render(request, 'phishing/index.html')

def analyze(request):
    """
    Handles the analysis of the provided email content.
    Expects a POST request with 'text' content.
    """
    if request.method == 'POST':
        text = request.POST.get('text', '').strip()

        if not text:
            return JsonResponse({'error': 'Please provide email content to analyze.'}, status=400)

        if len(text) > 10000:
            return JsonResponse({'error': 'Input text is too long. Please limit to 10,000 characters.'}, status=400)

        # Perform prediction
        result = detector.predict(text)
        # Get pre-calculated metrics
        metrics = detector.get_metrics()

        return JsonResponse({
            'result': result,
            'metrics': metrics,
        })

    return JsonResponse({'error': 'Invalid request method.'}, status=405)
