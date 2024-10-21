from pydantic import BaseModel, Field
from uuid import uuid4

class BaseTask(BaseModel):
    name: str | None = None
    query: dict | None = None  # Now a dictionary to store JSON inputs (traffic features)
    reference: int | None = None  # Now binary (0 or 1 for classification)
    task_id: str = Field(default_factory=lambda: str(uuid4()), allow_mutation=False)

    def make_query(self, feature_data: dict, **kwargs) -> dict:
        """Use the input traffic feature data as the query, excluding the 'label'."""
        # Remove the 'label' key from the feature_data if it exists
        feature_data_without_label = {k: v for k, v in feature_data.items() if k != 'label'}
        self.query = feature_data_without_label
        return self.query

    def make_reference(self, feature_data: dict) -> int:
        """Generate the expected classification result"""
        #Extracts Label from input features and use it as reference
        self.reference = feature_data.get('label', None) #default to None if label is missing
        return self.reference

    def generate_query_reference(self, feature_data: dict) -> tuple[dict, int]:
        """Generates a query (traffic features) and reference (classification)"""
        self.make_query(feature_data=feature_data)
        self.make_reference(feature_data=feature_data)
        return self.query, self.reference

