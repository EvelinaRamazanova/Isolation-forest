class Anomaly:
    def get_row(self):
        return self._row

    def get_score(self):
        return self._score

    def set_row(self, row):
        self._row = row

    def set_score(self, score):
        self._score = score

    row = property(get_row, set_row)
    score = property(get_score, set_score)
